"""The rule registry: permanent identity, alias resolution, one ordering."""

from __future__ import annotations

import json
import re

from trustsight.categories import RULE_CATEGORIES, RuleCategory
from trustsight.registry import REGISTRY, resolve, sort_key, uid_of
from trustsight.rule_id_history import RENAMED_RULE_IDS

_UID_RE = re.compile(r"^TS-\d{4}$")


def _uid_table() -> dict[str, str]:
    from importlib.resources import files

    data = files("trustsight").joinpath("registry_uids.json").read_text(encoding="utf-8")
    return json.loads(data)


def test_every_rule_has_an_opaque_uid():
    table = _uid_table()
    missing = sorted(set(RULE_CATEGORIES) - set(table))
    assert missing == [], f"rules with no uid: {missing}"


def test_uids_are_unique_and_well_formed():
    table = _uid_table()
    for rule_id, uid in table.items():
        assert _UID_RE.match(uid), f"{rule_id}: malformed uid {uid!r}"
    by_uid: dict[str, list[str]] = {}
    for rule_id, uid in table.items():
        by_uid.setdefault(uid, []).append(rule_id)
    collisions = {uid: ids for uid, ids in by_uid.items() if len(ids) > 1}
    assert collisions == {}, f"uids reused: {collisions}"


def test_registry_covers_every_categorised_rule():
    assert len(REGISTRY.all()) == len(RULE_CATEGORIES)
    assert {rule.id for rule in REGISTRY.all()} == set(RULE_CATEGORIES)


def test_every_renamed_id_resolves_to_its_survivor():
    for old, new in RENAMED_RULE_IDS.items():
        rule = resolve(old)
        assert rule is not None, f"{old} does not resolve"
        assert rule.id == new, f"{old} resolved to {rule.id}, expected {new}"
        assert uid_of(old) == uid_of(new) == rule.uid


def test_a_renamed_id_keeps_its_own_uid_constant():
    # The old spelling and the new spelling are the same rule, one uid.
    assert uid_of("R004") == uid_of("H001")


def test_reserved_and_unknown_ids_resolve_to_nothing():
    for name in ("R015", "R026", "R103", "NOPE", ""):
        assert resolve(name) is None
        assert uid_of(name) is None


def test_sort_key_is_series_major_and_stable():
    rules = REGISTRY.all()
    keys = [sort_key(rule) for rule in rules]
    assert keys == sorted(keys)
    # Grouping: every rule of a series is contiguous in the ordering.
    seen: set[str] = set()
    last = None
    for rule in rules:
        if rule.series != last:
            assert rule.series not in seen, f"{rule.series} is not contiguous"
            seen.add(rule.series)
            last = rule.series


def test_in_category_returns_only_that_category():
    integrity = REGISTRY.in_category(RuleCategory.INTEGRITY)
    assert integrity
    assert all(rule.category is RuleCategory.INTEGRITY for rule in integrity)
    expected = [rule.id for rule in REGISTRY.all() if rule.category is RuleCategory.INTEGRITY]
    assert [rule.id for rule in integrity] == expected
