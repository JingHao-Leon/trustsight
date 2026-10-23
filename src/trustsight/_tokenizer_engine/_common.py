"""Extracted from _tokenizer_engine.py: _common."""

import re
import threading

__all__ = ['_ARRAY_ASSIGNMENT_RE', '_ASSIGNMENT_RE', '_MAX_ARRAY_ENTRIES', '_MAX_EXPANSION_PASSES', '_MAX_LINE_LEN', '_MAX_TABLE_BYTES', '_MAX_VALUE_LEN', '_MEMO_ENTRIES', '_VAR_REF_RE', '_join_logical', '_memo', '_memoised', '_split_top_level', '_tail_continues']

# The bounds live with the shared resolver so the analysis and the worker
# read one value; re-exported here for the engine's own imports.
from ..expansion import (  # noqa: E402
    _MAX_EXPANSION_PASSES,
    _MAX_LINE_LEN,
    _MAX_TABLE_BYTES,
    _MAX_VALUE_LEN,
)

_memo = threading.local()

_MEMO_ENTRIES = 2

def _memoised(kind: str, key: str, compute):
    """Return ``compute()`` for *key*, reusing a recent identical object."""
    store = getattr(_memo, kind, None)
    if store is None:
        store = _memo.__dict__.setdefault(kind, [])
    for cached_key, cached_value in store:
        if cached_key is key:
            # A copy: callers receive a plain list they may treat as their
            # own, and a shared one would turn any future in-place edit
            # into a bug in an unrelated rule.
            return list(cached_value)
    value = compute()
    store.append((key, value))
    del store[:-_MEMO_ENTRIES]
    return list(value)

def _tail_continues(stripped_tail: str) -> bool:
    """True when a logical line ending in *stripped_tail* promises more.

    Bash continues without a backslash when the line ends in a pipe or a
    conditional operator: `curl url |` + newline + `bash` is one
    pipeline.  The two joiners must agree, or the rule path and the
    coverage path read different text from the same diff.

    A pipe preceded by an **odd** run of backslashes is escaped and is an
    ordinary character, so it promises nothing.  An even run is a literal
    backslash followed by a real operator, which does continue - the
    `endswith("\\|")` spelling this used to test counted `\\\\|` as
    escaped and split a live pipeline.
    """
    if stripped_tail.endswith("&&"):
        return True
    if not stripped_tail.endswith("|"):
        return False
    return _unescaped_at(stripped_tail, len(stripped_tail) - 1)


def _unescaped_at(text: str, index: int) -> bool:
    """True when ``text[index]`` is not escaped by a backslash run."""
    run = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        run += 1
        cursor -= 1
    return run % 2 == 0


def _backslash_continues(tail: str) -> bool:
    """True when *tail* ends in an unescaped backslash at the physical end.

    Two details bash cares about and the previous test did not.  A backslash
    with whitespace after it escapes that whitespace, so the newline is not
    escaped and the line does **not** continue; and a run of two backslashes
    is one literal backslash, not a continuation.  Only an odd run whose
    last character is the backslash continues the line.
    """
    run = 0
    for char in reversed(tail):
        if char != "\\":
            break
        run += 1
    return bool(run) and run % 2 == 1


def _join_logical(lines: list[str]) -> list[tuple[int, str]]:
    """Every logical line as ``(first_raw_index, marker + joined_text)``.

    The one implementation both joiners use, so the rule path and the
    coverage path cannot disagree about which physical lines the shell runs
    as one.  Two properties are bash's, not style choices:

    - A backslash-newline is removed and **nothing else is**.  The space in
      ``curl \\`` + newline + ``https://...`` separates two words at build
      time, so it stays; the previous ``rstrip`` glued them into
      ``curlhttps://...``.
    - A line continues only when the backslash is the last character and is
      not itself escaped.  ``echo \\ `` (backslash, space) and ``echo \\\\``
      (two backslashes) end the command, and joining them invented a
      command boundary the shell does not have.
    """
    out: list[tuple[int, str]] = []
    parts: list[str] | None = None
    marker = ""
    start_index = -1
    for index, line in enumerate(lines):
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            # Verbatim, exactly as the shell reads it: a backslash-newline
            # is removed, not replaced with whitespace.
            parts.append(body)
        else:
            if parts is not None:
                out.append((start_index, marker + "".join(parts)))
            parts, marker, start_index = [body], this_marker, index
        tail = parts[-1]
        if _backslash_continues(tail):
            parts[-1] = tail[:-1]
        elif _tail_continues(tail.rstrip()):
            pass  # still accumulating: an operator promises more input
        else:
            out.append((start_index, marker + "".join(parts)))
            parts, marker, start_index = None, "", -1
    if parts is not None:
        out.append((start_index, marker + "".join(parts)))
    return out

_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+"
    # Scalar option run (`declare -rx x=`, `declare +x`).  Only `r`/`x`
    # keep scalar-assignment semantics; `-n` is a nameref and `-a`/`-A`
    # are arrays - recording them as scalars collapsed the nameref
    # `declare -n R=C` to a literal and hid the X002 command it aliases.
    r"(?:(?:--?|\+\+?)[rx]+\s+){0,4})?(\w+)\s*(\+?=)\s*(.*)"
)

_ARRAY_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:local|export|declare|readonly|typeset)\s+"
    r"(?:(?:--?|\+\+?)[rx]+\s+){0,4})?(\w+)\s*(\+?=)\s*\((.*)"
)

_VAR_REF_RE = re.compile(r"\$\{(\w+)\}(?!\[)|\$(\w+)")

def _split_top_level(body: str) -> list[str]:
    """*body* split on command separators, respecting quotes.

    Reuses the crossfire splitter rather than growing a second one here.
    Imported lazily: :mod:`analysis.crossfire` imports this module's
    public tokenizer at module level, so a top-level import would close
    the loop.
    """
    from ..analysis.crossfire import _split_commands
    return _split_commands(body)

#: An array may contribute at most this many entries to the table.  Without
#: it, one 5 MiB line of tiny words builds a multi-million-element list
#: before the table-size check is ever reached.
_MAX_ARRAY_ENTRIES = 4096
