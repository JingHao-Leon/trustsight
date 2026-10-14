"""Extracted from crossfire.py: _ownership."""

from __future__ import annotations

__all__ = ['CROSSFIRE_OWNERSHIP', '_ownership_yields', 'resolve_ownership', 'resolve_ownership_audit']

CROSSFIRE_OWNERSHIP = (
    ("X002", ("X001",)),   # a decoded-then-executed name is X001's
    ("X009", ("X001",)),
    ("X015", ("X011",)),   # dependency-array words belong to X011
    ("X023", ("X009",)),   # a resolved uncatalogued fetch is X009's
)

def _ownership_yields(found: dict) -> dict[int, str]:
    """The winning owner for each contested line, from the table."""
    yields = dict(CROSSFIRE_OWNERSHIP)
    owners_by_line: dict[int, set[str]] = {}
    for rule_id, hits in found.items():
        for hit in hits:
            owners_by_line.setdefault(hit[0], set()).add(rule_id)
    winner: dict[int, str] = {}
    for rule_id, hits in found.items():
        superseded = set(yields.get(rule_id, ()))
        for hit in hits:
            contenders = superseded & owners_by_line.get(hit[0], set())
            for owner in contenders:
                winner.setdefault(hit[0], owner)
    return winner

def resolve_ownership(found: dict) -> dict:
    """Assign each matched line exactly one owner.

    A rule yields on a line when an owner it yields to matched the same
    line.  Returns a new dict; the input is left untouched.
    """
    if not found:
        return found
    yields = dict(CROSSFIRE_OWNERSHIP)
    owners_by_line: dict[int, set[str]] = {}
    for rule_id, hits in found.items():
        for hit in hits:
            owners_by_line.setdefault(hit[0], set()).add(rule_id)
    resolved: dict = {}
    for rule_id, hits in found.items():
        superseded = set(yields.get(rule_id, ()))
        kept = [
            hit for hit in hits
            if not (superseded & owners_by_line.get(hit[0], set()))
        ]
        if kept:
            resolved[rule_id] = kept
    return resolved

def resolve_ownership_audit(found: dict) -> dict[str, list[tuple]]:
    """Every produced record with its ``resolved_by``.

    The public :func:`resolve_ownership` returns owners only, so a record it
    drops is invisible.  This audit keeps every record and names the owner a
    contested line yielded to (``None`` when the record owns its line), so the
    stand-down can be checked against the table as data.
    """
    if not found:
        return {}
    winner = _ownership_yields(found)
    out: dict[str, list[tuple]] = {}
    for rule_id, hits in found.items():
        audited = []
        for hit in hits:
            line, shape, quoted = hit[0], hit[1], hit[2]
            owner = winner.get(line)
            resolved_by = owner if owner and owner != rule_id else None
            audited.append((line, shape, quoted, resolved_by))
        out[rule_id] = audited
    return out
