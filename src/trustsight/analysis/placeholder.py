"""H104: a placeholder package - a name claimed, nothing installed.

A package whose recipe is a stub reserves a name in the AUR without shipping
anything: ``pkgver`` 0.0.0, a ``package()`` body that only echoes, and a dummy
or empty checksum.  Individually it is inert - it builds and installs nothing
- so the risk is not the recipe but the name it claims, which is why G011
watches a maintainer that does it many times.

Signal is absolute state, not a change: a placeholder reads the same whether
it is first seen or edited, so this is called from the recipe text on the
fresh path, the incremental path and ``trustsight lint`` alike.  It is weight
0 - a declared fact about the recipe, surfaced for a human, never scored.
"""

from __future__ import annotations

import re

__all__ = ["placeholder_finding", "is_placeholder_recipe"]

#: pkgver values that read as a not-yet-versioned reservation.
_PLACEHOLDER_PKGVER_RE = re.compile(r"^0\.0\.0(?:[.\-+]|$)")

#: A dummy checksum sentinel.  ``DUMMY-FOR-INITIALIZATION`` is the one seen in
#: the wild; a single distinct character repeated is the shape makepkg never
#: produces and H083 already treats as unpinned.
_DUMMY_SUM_RE = re.compile(r"(?i)dummy|placeholder|^x{4,}$|^0{4,}$")

#: Verbs that put a file into the package root.  A package function with none
#: of these ships nothing.
_SHIP_VERB_RE = re.compile(
    r"\b(?:cp|install|mv|mkdir|ln|dd|tee|rsync|make|ninja|cargo|pip|npm|"
    r"meson|cmake|configure|strip)\b"
)

#: Statements that are noise, not shipping.
_NOOP_STMT_RE = re.compile(r"^(?:echo|printf|true|:|return(?:\s+\d+)?|"
                           r"exit(?:\s+\d+)?)\b")


def _package_bodies(functions: dict) -> list[str]:
    """Bodies of every ``package``/``package_*`` function."""
    return [body for name, body in functions.items()
            if name == "package" or name.startswith("package_")]


def _body_ships_nothing(body: str) -> bool:
    """True when a package function contains no install action.

    Comments are dropped and only real statements are judged; an empty body
    also ships nothing.  Unresolved content is read as text, like every other
    structural rule.
    """
    from ..line_lex import strip_comment

    for raw in body.splitlines():
        line = strip_comment(raw).strip()
        if not line:
            continue
        if _NOOP_STMT_RE.match(line):
            continue
        if _SHIP_VERB_RE.search(line):
            return False
        # A redirect into the staged tree is shipping even without a verb.
        if re.search(r">\s*\"?\$(?:pkgdir|DESTDIR)", line):
            return False
    return True


def is_placeholder_recipe(text: str) -> tuple[bool, str | None]:
    """Whether *text* is a stub recipe, and why.

    Fires on **two of three** signals: a ``0.0.0`` version, a package body
    that ships nothing, a dummy or empty checksum.  The conjunction keeps a
    legitimate ``0.0.0`` package (a real project pinned at the zero release)
    or an unusual-but-real package function from reading as a reservation.
    """
    if not text:
        return False, None
    from ..recipedoc import parse_recipe
    from .structural import _is_checksum_array

    recipe = parse_recipe(text, file="PKGBUILD")

    signals: list[str] = []

    pkgver = str(recipe.scalars.get("pkgver", "") or "").strip().strip("\"'")
    if _PLACEHOLDER_PKGVER_RE.match(pkgver):
        signals.append("pkgver is 0.0.0")

    bodies = _package_bodies(recipe.functions)
    if bodies and all(_body_ships_nothing(b) for b in bodies):
        signals.append("package() installs nothing")

    sums = [
        entry
        for name, entries in recipe.arrays.items()
        if _is_checksum_array(name)
        for entry in entries
    ]
    dummy = [s for s in sums if _DUMMY_SUM_RE.search(str(s).strip())]
    empty = not sums and not recipe.arrays.get("source")
    if dummy:
        signals.append("checksum is a dummy sentinel")
    elif empty:
        signals.append("no source and no checksum declared")

    if len(signals) >= 2:
        return True, "; ".join(signals)
    return False, None


def placeholder_finding(text: str | None) -> dict | None:
    """H104 for a recipe's text, or None when it is not a placeholder."""
    from ..findings import stamp

    is_placeholder, reason = is_placeholder_recipe(text or "")
    if not is_placeholder:
        return None
    pkgname = ""
    try:
        from ..recipedoc import parse_recipe

        pkgname = str(
            parse_recipe(text or "", file="PKGBUILD").scalars.get("pkgname", "")
            or ""
        ).strip().strip("\"'")
    except Exception:  # noqa: BLE001 - a name is a nicety, not the finding
        pkgname = ""
    return stamp({
        "rule_id": "H104", "name": "Placeholder Package",
        "severity": "INFO", "category": "naming",
        "weight_override": 0,
        "match": f"placeholder package: {reason}"
                 + (f" (claims '{pkgname}')" if pkgname else ""),
        "file": "PKGBUILD", "line": None,
        "params": {"reason": reason, "pkgname": pkgname},
    })
