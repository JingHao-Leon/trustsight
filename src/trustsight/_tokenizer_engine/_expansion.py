"""Re-exports the shared parameter-expansion resolver.

The implementation lives in :mod:`trustsight.expansion` so the parent
analysis can resolve a PKGBUILD's own variables without importing this
sandboxed package (A6 forbids the parent importing ``_tokenizer_engine``).
This module keeps the worker's import surface unchanged.
"""

from ..expansion import (
    _INNERMOST_RE,
    _REPLACEMENT_ESCAPE_RE,
    _expand_one,
    _glob_to_regex,
    _strip_affix,
    resolve_expansions,
)

__all__ = [
    "_INNERMOST_RE",
    "_REPLACEMENT_ESCAPE_RE",
    "_expand_one",
    "_glob_to_regex",
    "_strip_affix",
    "resolve_expansions",
]
