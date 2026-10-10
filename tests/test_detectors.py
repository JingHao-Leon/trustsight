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
