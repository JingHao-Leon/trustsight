"""Extracted from _tokenizer_engine.py: _common."""

import re
import threading

__all__ = ['_ARRAY_ASSIGNMENT_RE', '_ASSIGNMENT_RE', '_MAX_EXPANSION_PASSES', '_MAX_LINE_LEN', '_MAX_TABLE_BYTES', '_MAX_VALUE_LEN', '_MEMO_ENTRIES', '_VAR_REF_RE', '_memo', '_memoised', '_split_top_level', '_tail_continues']

# The cap now lives with the shared resolver so the analysis and the worker
# read one value; re-exported here for the engine's own imports.
from ..expansion import _MAX_EXPANSION_PASSES  # noqa: E402

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
    """
    return ((stripped_tail.endswith("|")
             and not stripped_tail.endswith("\\|"))
            or stripped_tail.endswith("&&"))

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

_MAX_VALUE_LEN = 8192

_MAX_LINE_LEN = 65536

_MAX_TABLE_BYTES = 1 << 20
