"""The artifact corpus is a committed negative-control set for the A-series."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from calibration._gates import gate_artifact_corpus  # noqa: E402


def test_artifact_corpus_gate_passes():
    gate = gate_artifact_corpus()
    assert gate.passed, gate.detail


def test_font_manifest_is_the_negative_control():
    import json
    from trustsight.analysis.artifact import inspect_manifest

    root = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "artifact-corpus"
    doc = json.loads((root / "data_fonts.json").read_text())
    assert inspect_manifest(doc["manifest"], doc["declared"]) == []
