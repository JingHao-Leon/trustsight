"""Extracted from _tokenizer_engine.py: _expansion."""

import re
from ._common import _MAX_EXPANSION_PASSES

__all__ = ['_INNERMOST_RE', '_REPLACEMENT_ESCAPE_RE', '_expand_one', '_glob_to_regex', '_strip_affix', 'resolve_expansions']

_INNERMOST_RE = re.compile(r"\$\{([^{}]*)\}")

_REPLACEMENT_ESCAPE_RE = re.compile(r"\\(.)")

def _glob_to_regex(pat: str, greedy: bool = True) -> re.Pattern:
    """Translate a bash glob pattern to a regex.  Bash character classes
    and metacharacters are translated; everything else is escaped so that
    dots, hyphens, etc. are literals rather than regex operators.

    ``greedy=False`` translates ``*`` non-greedily, which is what the
    shortest-match affix operators (``#``/``%``) need."""
    out: list[str] = []
    star = ".*" if greedy else ".*?"
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            out.append(star)
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                cls = pat[i + 1 : j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))

def _strip_affix(val: str, op: str, pat: str) -> str:
    """Apply bash ## / # / %% / % stripping using glob patterns.

    The operators differ on two axes at once: ``#``/``##`` match a prefix
    of the value and ``%``/``%%`` a suffix, and the single character
    removes the SHORTEST match while the doubled removes the LONGEST.
    Anchoring is part of the contract: ``${v##foo}`` on ``barfoo`` removes
    nothing because ``foo`` is no prefix, and ``${v#*/}`` on ``a/b/c``
    leaves ``b/c`` (the shortest matching prefix), not ``c``.

    For the suffix forms the pattern is wrapped in a ``.*`` prefix and
    end-anchored: greedy, the prefix claims as much as it can and the
    group starts as late as possible (shortest suffix); lazy, it yields
    as little as it can (longest suffix).
    """
    if op == "#":
        m = _glob_to_regex(pat, greedy=False).match(val)
        return val[m.end():] if m else val
    if op == "##":
        m = _glob_to_regex(pat).match(val)
        return val[m.end():] if m else val
    if op == "%":
        m = re.compile(r".*(" + _glob_to_regex(pat).pattern + r")\Z").match(val)
        return val[: m.start(1)] if m else val
    if op == "%%":
        m = re.compile(r".*?(" + _glob_to_regex(pat).pattern + r")\Z").match(val)
        return val[: m.start(1)] if m else val
    return val

def _expand_one(
    body: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
) -> str | None:
    """Resolve a single innermost ${...} body.

    *body* is the content between ${ and }; all nested expansions have
    already been resolved at this point, so no further ${...} remains.

    Returns None (unresolved) for forms we refuse to evaluate.
    """
    arrays = arrays or {}

    # Indirect expansion and length: never resolve.
    if body.startswith("!") or body.startswith("#"):
        return None

    # Array element or whole-array expansion.
    m = re.match(r"^(\w+)\[(\*|@|\d+)\]$", body)
    if m:
        name, idx = m.group(1), m.group(2)
        arr = arrays.get(name)
        if arr is None:
            return None
        if idx in ("*", "@"):
            return " ".join(arr)
        i = int(idx)
        return arr[i] if 0 <= i < len(arr) else ""

    # //pat/rep  |  //pat  (delete)  |  /pat/rep
    m = re.match(r"^(\w+)(//|/)([^/]*)(?:/(.*))?$", body)
    if m:
        name, mode, pat, rep = m.group(1), m.group(2), m.group(3), m.group(4) or ""
        val = vars_.get(name)
        if val is None:
            # Bash treats an unset scalar in ${var/pat/rep} as empty.
            return ""
        # The replacement is bash text, not a re.sub template: a backslash
        # quotes the next character and everything else stands for itself.
        # Fed raw, a legal `${x/a/\q}` raised re.error, which the sandbox
        # escalated to TokenizerUnavailable - one odd expansion must leave
        # that expansion unresolved, not the whole package unvetted.  The
        # substitution goes through a function so the text is literal.
        rep = _REPLACEMENT_ESCAPE_RE.sub(r"\1", rep)
        try:
            regex = _glob_to_regex(pat)
            if mode == "//":
                return regex.sub(lambda _match: rep, val)
            return regex.sub(lambda _match: rep, val, count=1)
        except re.error:
            # A pattern we cannot compile is refused, not fatal.
            return None

    # ,, , ^^ ^ - case conversion.  `${c,,}` on `c=CURL` is `curl`, which
    # is a command name assembled out of a case operator: the payload rules
    # match `curl` and saw `${c,,}`.  X002 caught it as a *technique*, which
    # is the family's job only while the tokenizer cannot do this one.
    #
    # The optional pattern after the operator restricts which characters
    # convert, and is not resolved: `${c,,[!a]}` is refused rather than
    # guessed at, because a wrong expansion is worse than an unresolved one.
    m = re.match(r"^(\w+)(,,|,|\^\^|\^)$", body)
    if m:
        name, op = m.group(1), m.group(2)
        val = vars_.get(name)
        if val is None:
            return None
        if op == ",,":
            return val.lower()
        if op == ",":
            return val[:1].lower() + val[1:]
        if op == "^^":
            return val.upper()
        return val[:1].upper() + val[1:]

    # arr[@]:offset:length - an array slice.  `${a[@]:0:1}` on `a=(curl x)`
    # is `curl`; the slice is how the name gets past a scan that reads the
    # whole array or nothing.
    m = re.match(r"^(\w+)\[(?:\*|@)\]:(\d+)(?::(\d+))?$", body)
    if m:
        name, off, length = m.group(1), int(m.group(2)), m.group(3)
        arr = arrays.get(name)
        if arr is None:
            return None
        end = off + int(length) if length else len(arr)
        return " ".join(arr[off:end])

    # ##pat  #pat  %%pat  %pat
    m = re.match(r"^(\w+)(##|#|%%|%)(.*)$", body)
    if m:
        name, op, pat = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return ""
        try:
            return _strip_affix(val, op, pat)
        except re.error:
            # A pattern we cannot compile is refused, not fatal.
            return None

    # :-default  /  :=default
    m = re.match(r"^(\w+):([-=])(.*)$", body)
    if m:
        name, _, default = m.group(1), m.group(2), m.group(3)
        return vars_.get(name) or default

    # :offset:length  /  :offset
    m = re.match(r"^(\w+):(\d+)(?::(\d+))?$", body)
    if m:
        name, off, length = m.group(1), m.group(2), m.group(3)
        val = vars_.get(name)
        if val is None:
            return ""
        return val[int(off) : int(off) + int(length)] if length else val[int(off) :]

    # plain variable reference
    if re.fullmatch(r"\w+", body):
        if body in arrays:
            arr = arrays[body]
            return arr[0] if arr else ""
        return vars_.get(body)

    return None

def resolve_expansions(
    text: str,
    vars_: dict[str, str],
    arrays: dict[str, list[str]] | None = None,
) -> tuple[str, bool]:
    """Resolve nested ${...} parameter expansions innermost-first.

    Returns (resolved_text, fully_resolved).
    fully_resolved is False if any ${...} remains after the cap; the caller
    MUST treat that as unresolved, never as a literal value.
    """
    arrays = arrays or {}
    all_resolved = True
    for _ in range(_MAX_EXPANSION_PASSES):
        before = text
        m = _INNERMOST_RE.search(text)
        if m is None:
            return text, all_resolved and "${" not in text
        replacement = _expand_one(m.group(1), vars_, arrays)
        if replacement is None:
            all_resolved = False
        else:
            text = text[: m.start()] + replacement + text[m.end() :]
        if text == before:
            return text, all_resolved and "${" not in text
    return text, False
