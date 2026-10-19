"""Stable rule identity and the one ordering every view derives from.

A rule's identifier does several jobs at once today: it is the citation key
stored reports, baselines and ``config.toml`` overrides use, it tags the
detection *mechanism* (``R`` regex, ``H`` heuristic, ``C`` confluence, ...),
and its number implies sequence.  Those jobs conflict: an id cannot be
scannable, immutable and allocated-at-creation at the same time, and
TrustSight chose immutable, so the numbers drifted (``R048`` sits next to
``R152``).

This module separates the jobs:

* :attr:`Rule.uid` is the **identity** - opaque, permanent, never reused.
  It is recorded once in ``registry_uids.json`` (see
  ``scripts/build_registry_uids.py``) and reported alongside the id so a
  stored artifact can be joined to a rule no matter how the rule is later
  renamed.
* :attr:`Rule.id` is a **display handle**.  It may be renamed; every former
  value stays resolvable through :meth:`Registry.resolve` (the rename and
  retirement tables in :mod:`trustsight.rule_id_history`).
* :attr:`Rule.category` and :attr:`Rule.series` are **metadata** - the
  subject a rule is filed under and the mechanism that emits it.  Neither is
  encoded in the identity.
* :attr:`Rule.sort_key` is the single ordering used by every view (docs
  bodies, page indexes, the catalog, the CLI listing), so those views cannot
  disagree the way the hand-ordered documentation currently does.
* The display metadata (:attr:`Rule.name`, ``severity``, ``capability``,
  ``target``) comes from ``registry_meta.json``, so the reference pages and
  the catalog are rendered from one record instead of the section prose.

Nothing here changes what a finding contains or how a rule scores; it is a
lookup layer over data that already ships.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files

from .categories import RULE_CATEGORIES, RuleCategory
from .rule_id_history import (
    ANCHOR_RULE_IDS,
    RENAMED_RULE_IDS,
    RETIRED_RULE_IDS,
    survivor_id,
)

__all__ = [
    "Rule",
    "Registry",
    "REGISTRY",
    "SECTION_META",
    "resolve",
    "uid_of",
    "sort_key",
]

#: A rule a code path emits.
STATUS_LIVE = "live"
#: A rule kept only so its reference anchor and citations resolve.
STATUS_ANCHOR = "anchor"

_UIDS_FILE = "registry_uids.json"
_META_FILE = "registry_meta.json"


def _load_section_meta() -> dict[str, dict]:
    data = files("trustsight").joinpath(_META_FILE).read_text(encoding="utf-8")
    return json.loads(data)


#: anchor -> the section's display metadata.  Two sections can share a rule
#: (H026 has a per-package and a corpus path); exactly one is ``canonical``
#: and names the rule itself.
SECTION_META: dict[str, dict] = _load_section_meta()


def _series_of(rule_id: str) -> str:
    """The mechanism letter an id leads with, or ``""``."""
    return rule_id[:1] if rule_id else ""


def _number_of(rule_id: str) -> int:
    """The numeric part of an id, or 0 when it has none."""
    digits = rule_id[1:]
    return int(digits) if digits.isdigit() else 0


@dataclass(frozen=True, slots=True)
class Rule:
    """One rule: an opaque identity plus its current, mutable handles."""

    uid: str
    id: str
    category: RuleCategory
    series: str
    status: str
    aliases: tuple[str, ...] = ()
    #: Display metadata (from ``registry_meta.json``): the name the reference
    #: and catalog show, the documented severity (its text and worst word),
    #: the capability a finding carries, and where the rule is configured.
    name: str | None = None
    severity: str | None = None
    severity_text: str | None = None
    capability: str | None = None
    target: str | None = None

    @property
    def sort_key(self) -> tuple[str, int, str]:
        """The one ordering every generated view uses.

        Series-major (``C001`` before ``H026`` before ``R001``), so the
        catalog, the page indexes and the CLI listing read as families
        rather than as one interleaved run of numbers.
        """
        return (self.series, _number_of(self.id), self.id)


class Registry:
    """Every rule this build knows, joinable by current or historical id."""

    def __init__(self) -> None:
        data = files("trustsight").joinpath(_UIDS_FILE).read_text(encoding="utf-8")
        uids: dict[str, str] = json.loads(data)

        # Historical id -> current id, for every renamed and retired rule.
        aliases: dict[str, str] = {}
        aliases.update(RETIRED_RULE_IDS)
        aliases.update(RENAMED_RULE_IDS)

        named = {e["uid"]: e for e in SECTION_META.values() if e.get("canonical")}

        self._rules: dict[str, Rule] = {}
        self._by_uid: dict[str, Rule] = {}
        for rule_id, category in RULE_CATEGORIES.items():
            uid = uids.get(rule_id)
            if uid is None:
                raise RuntimeError(
                    f"{rule_id} has no uid; run scripts/build_registry_uids.py"
                )
            status = STATUS_ANCHOR if rule_id in ANCHOR_RULE_IDS else STATUS_LIVE
            entry = named.get(uid, {})
            rule = Rule(
                uid=uid,
                id=rule_id,
                category=category,
                series=_series_of(rule_id),
                status=status,
                aliases=tuple(sorted(a for a, target in aliases.items() if target == rule_id)),
                name=entry.get("name"),
                severity=entry.get("severity"),
                severity_text=entry.get("severity_text"),
                capability=entry.get("capability"),
                target=entry.get("target"),
            )
            self._rules[rule_id] = rule
            self._by_uid[uid] = rule

    def __contains__(self, name: str) -> bool:
        return self.resolve(name) is not None

    def resolve(self, name: str | None) -> Rule | None:
        """A current id, a former id, or a ``uid`` -> its :class:`Rule`.

        Returns ``None`` for an id that names no rule (reserved, unassigned,
        or simply unknown) rather than raising: callers read ids out of
        stored findings and old baselines, where an unknown id is a fact
        about the data.
        """
        if not name:
            return None
        name = name.strip()
        if name in self._by_uid:
            return self._by_uid[name]
        return self._rules.get(survivor_id(name))

    def uid_of(self, name: str | None) -> str | None:
        """The permanent uid behind *name*, or ``None`` if it is not a rule."""
        rule = self.resolve(name)
        return rule.uid if rule is not None else None

    def all(self) -> list[Rule]:
        """Every rule, in the one shared ordering."""
        return sorted(self._rules.values(), key=lambda rule: rule.sort_key)

    def in_category(self, category: RuleCategory) -> list[Rule]:
        """Every rule filed under *category*, in the one shared ordering."""
        return [rule for rule in self.all() if rule.category is category]


REGISTRY = Registry()


def resolve(name: str | None) -> Rule | None:
    """See :meth:`Registry.resolve`."""
    return REGISTRY.resolve(name)


def uid_of(name: str | None) -> str | None:
    """See :meth:`Registry.uid_of`."""
    return REGISTRY.uid_of(name)


def sort_key(rule: Rule) -> tuple[str, int, str]:
    """See :attr:`Rule.sort_key`."""
    return rule.sort_key
