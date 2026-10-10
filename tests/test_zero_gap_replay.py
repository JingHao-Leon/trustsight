"""Spec §2: the truncation gap never fires on healthy input.

The truncation check hardens every feature that trusts ``DiffDoc``
completeness, so the property that matters is the negative one: a
well-formed diff (the whole locked corpus, every malicious fixture) must
produce *no* truncation gap and no lost finding.  The default suite scans
every 37th benign diff plus every labelled fixture; the full replay the
calibration job already exercises is the same check at stride 1.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness.diffdoc_parity import FIXTURES, iter_diff_paths  # noqa: E402

from trustsight.analysis.pipeline import scan_diff  # noqa: E402
from trustsight.coverage import DIFF_TRUNCATED  # noqa: E402

CORPUS = FIXTURES / "benign-corpus"
MALICIOUS = FIXTURES / "malicious"

corpus_mark = pytest.mark.skipif(
    not CORPUS.exists(),
    reason="benign corpus absent; rebuild with scripts/build_corpus.py",
)

BENIGN_SAMPLE = [
    path for path in iter_diff_paths(sample=37) if CORPUS in path.parents
]
MALICIOUS_ALL = sorted(MALICIOUS.rglob("*.diff")) if MALICIOUS.exists() else []


def _assert_no_gap(path: Path) -> None:
    fact = scan_diff(path.read_text(errors="replace"), package_name=path.stem)
    assert DIFF_TRUNCATED not in fact.coverage_gaps, (
        f"{path.name}: a well-formed diff produced {DIFF_TRUNCATED}"
    )


@corpus_mark
@pytest.mark.parametrize("path", BENIGN_SAMPLE, ids=lambda p: p.name)
def test_benign_corpus_has_no_truncation_gap(path):
    _assert_no_gap(path)


@pytest.mark.skipif(not MALICIOUS_ALL, reason="malicious fixtures absent")
@pytest.mark.parametrize("path", MALICIOUS_ALL, ids=lambda p: p.name)
def test_malicious_fixtures_have_no_truncation_gap(path):
    _assert_no_gap(path)
