"""Detector metadata: mechanism, subject, evidence and shared dependencies."""

from trustsight.categories import RULE_CATEGORIES
from trustsight.detectors import detector_metadata


def test_every_rule_has_detector_metadata():
    for rule_id in RULE_CATEGORIES:
        meta = detector_metadata(rule_id)
        assert meta, rule_id
        assert meta["mechanism"], rule_id
        assert meta["subject"], rule_id
        assert meta["shared_dependencies"], rule_id


def test_shared_dependencies_surface_common_mode_failure():
    # R (regex) and X (evasion) are different mechanisms but share the
    # tokenizer: the dependency is named, not assumed away.
    assert "tokenizer" in detector_metadata("R001")["shared_dependencies"]
    assert "tokenizer" in detector_metadata("X001")["shared_dependencies"]


def test_unknown_rule_has_no_metadata():
    assert detector_metadata("P999") is None


def test_h056_reports_the_indicator_mechanism_not_the_h_series():
    """H056 carries an H id but the indicator mechanism; the override makes
    the registry honest about its evidence and dependencies."""
    from trustsight.categories import RuleCategory

    meta = detector_metadata("H056")
    assert meta["subject"] == RuleCategory.INDICATOR.value
    assert meta["mechanism"] == "external indicator membership"
    assert meta["evidence"] == "signed indicator baselines"
    assert "ioc_baseline" in meta["shared_dependencies"]
    assert "tokenizer" not in meta["shared_dependencies"]


def test_the_indicator_category_holds_h056_and_no_i_id_yet():
    from trustsight.categories import RuleCategory, category_of, rules_in

    assert rules_in(RuleCategory.INDICATOR) == ["H056"]
    assert category_of("H056") is RuleCategory.INDICATOR
    # No I-prefixed rule id ships yet; new federation matches take them.
    assert not [rid for rid in RULE_CATEGORIES if rid.startswith("I")]
