"""Addendum 3: the H-series reduction's enforceable machinery.

The plan's hard invariants: the intake freeze (no new H id while the live
count is above target) and the retirement alias (a retired id resolves to
its survivor and is never reused).  The actual mergers are a data change
once the co-fire audit is measured; these tests guard the mechanism.
"""

from trustsight.categories import RULE_CATEGORIES
from trustsight.rule_id_history import (
    FROZEN_H_IDS,
    RETIRED_RULE_IDS,
    survivor_id,
)


def test_no_new_h_id_is_added():
    """The intake freeze: a new H id fails this until the target is reached."""
    current_h = {rid for rid in RULE_CATEGORIES if rid.startswith("H")}
    new = sorted(current_h - FROZEN_H_IDS)
    assert not new, f"new H id(s) added during the intake freeze: {new}"


def test_retired_ids_are_not_reused():
    retired = set(RETIRED_RULE_IDS)
    live = {rid for rid in RULE_CATEGORIES}
    assert not (retired & live), "a retired id is still live"
    # The freeze never re-issues a retired id either.
    assert not (retired & FROZEN_H_IDS)


def test_survivors_are_live_and_not_themselves_retired():
    for old, survivor in RETIRED_RULE_IDS.items():
        assert survivor not in RETIRED_RULE_IDS, f"{old} -> a retired survivor"
        assert survivor in RULE_CATEGORIES, f"{old} -> unknown survivor {survivor}"


def test_survivor_id_follows_a_retirement_and_a_rename():
    # R004 was renamed to H001; the rename path still resolves.
    assert survivor_id("R004") == "H001"
    # An id that is neither retired nor renamed is returned unchanged.
    assert survivor_id("H001") == "H001"


def test_a_synthetic_retirement_resolves_to_its_survivor(monkeypatch):
    import trustsight.rule_id_history as history

    monkeypatch.setitem(history.RETIRED_RULE_IDS, "H999", "H001")
    assert survivor_id("H999") == "H001"


def test_an_override_on_a_retired_id_still_suppresses_the_survivor(monkeypatch):
    import trustsight.rule_id_history as history
    from trustsight import override

    monkeypatch.setitem(history.RETIRED_RULE_IDS, "H999", "H001")
    monkeypatch.setattr(
        override, "load_overrides",
        lambda: [override.RuleOverride(rule_id="H999", reason="retired")],
    )
    kept, suppressed = override.filter_triggered_rules(
        [{"rule_id": "H001", "severity": "HIGH"}])
    assert kept == []
    assert suppressed[0]["rule_id"] == "H001"


def test_cofire_row_measures_the_shared_firings():
    """Phase 5 Step 1: the co-fire ratio is over the rarer rule's firings."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import h_reduction_audit as audit

    benign = {"H016": {1, 2, 3}, "H042": {2, 3}}
    mal_sets: dict = {}
    mal_counts: dict = {}
    row = audit.cofire_row("H016", "H042", benign, mal_sets, mal_counts, 0.95)
    # 2 shared of the rarer rule's 2 firings -> merge candidate.
    assert row["both"] == 2
    assert row["ratio_of_rarer"] == 1.0
    assert row["meets_epsilon"]

    distinct = audit.cofire_row("H016", "H999", benign, mal_sets, mal_counts, 0.95)
    assert distinct["both"] == 0
    assert not distinct["measured"]
    assert not distinct["meets_epsilon"]


def _security_gates():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import security_gates

    return security_gates


def test_live_ceiling_is_the_frozen_set_minus_anchors():
    from trustsight.rule_id_history import ANCHOR_RULE_IDS

    sg = _security_gates()
    assert sg._h_series_live_ceiling() == len(FROZEN_H_IDS) - len(ANCHOR_RULE_IDS)


def test_intake_gate_fails_on_a_new_h_id(monkeypatch):
    from trustsight import categories

    sg = _security_gates()
    monkeypatch.setitem(categories.RULE_CATEGORIES, "H999",
                        categories.RULE_CATEGORIES["H001"])
    gate = sg.gate_h_series_intake_is_frozen()
    assert not gate.passed
    assert any("H999" in str(p) for p in gate.detail)


def test_residue_gate_fails_above_the_frozen_ceiling(monkeypatch):
    from trustsight import categories

    sg = _security_gates()
    assert sg.gate_h_series_reduction_residue().passed
    monkeypatch.setitem(categories.RULE_CATEGORIES, "H999",
                        categories.RULE_CATEGORIES["H001"])
    gate = sg.gate_h_series_reduction_residue()
    assert not gate.passed
