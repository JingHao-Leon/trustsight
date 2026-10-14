"""Extracted from structural.py: _common."""

import re

__all__ = ['_BINARY_ARTIFACT_RE', '_TRUSTED_BUCKETS']

_BINARY_ARTIFACT_RE = re.compile(
    r"\.(?:bin|exe|elf|so|dll|dylib|appimage|deb|rpm|apk|msi|jar|run)"
    r"(?:\?|#|$)",
    re.IGNORECASE,
)

_TRUSTED_BUCKETS = frozenset({"trusted_forge", "official"})
