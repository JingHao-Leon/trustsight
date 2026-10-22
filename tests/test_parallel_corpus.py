"""Serial vs parallel corpus runner equality.

The parallel path precomputes each package's global-URL prefix exactly and
lets each worker process its diffs serially, so it must produce the serial
rows.  A synthetic corpus makes the shared-URL case deterministic and fast.
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import calibration_gates as gates  # noqa: E402

# The runner forks deliberately: pattern-safety verdicts are decided in the
# parent and inherited, and each child resets its inherited database and
# tokenizer state.  CPython warns about fork from a threaded process (the
# test runner), which is noise here.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

_DIFF_A = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=aaa\n"
    "+pkgver=1\n"
    "+source=('https://shared.example/x.tar.gz')\n"
)
_DIFF_B = (
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1,3 @@\n"
    "+pkgname=bbb\n"
    "+pkgver=1\n"
    "+source=('https://shared.example/x.tar.gz')\n"
)


def _write_corpus(root: Path) -> Path:
    corpus = root / "benign-corpus"
    corpus.mkdir()
    (corpus / "aaa__1..2.diff").write_text(_DIFF_A)
    (corpus / "bbb__1..2.diff").write_text(_DIFF_B)
    return corpus


def test_the_plan_prefix_carries_a_previous_packages_urls():
    with tempfile.TemporaryDirectory() as tmp:
        corpus = _write_corpus(Path(tmp))
        with gates.shipped_config():
            config = gates.load_config()
            plan = gates._benign_plan(corpus, sample=1, config=config)
        prefixes = {pkg: prefix for pkg, _paths, prefix in plan}
        assert "https://shared.example/x.tar.gz" in prefixes["bbb"]
        assert "https://shared.example/x.tar.gz" not in prefixes["aaa"]


def test_parallel_rows_equal_serial_rows():
    with tempfile.TemporaryDirectory() as tmp:
        corpus = _write_corpus(Path(tmp))
        with gates.shipped_config():
            serial = gates.scan_corpus(corpus, sample=1, jobs=1)
            parallel = gates.scan_corpus(corpus, sample=1, jobs=2)
    assert serial == parallel


def test_sharded_rows_merge_to_the_whole_scan():
    """A shard is a slice of the plan, not a different measurement."""
    with tempfile.TemporaryDirectory() as tmp:
        corpus = _write_corpus(Path(tmp))
        with gates.shipped_config():
            full = gates.scan_corpus_tasks(corpus, sample=1, jobs=1)
        parts = []
        for index in range(3):
            with gates.shipped_config():
                parts += gates.scan_corpus_tasks(
                    corpus, sample=1, jobs=1, shard=(index, 3))
        merged = [rows for _index, rows in sorted(parts, key=lambda t: t[0])]
        assert merged == [rows for _index, rows in full]


def test_shard_artifact_round_trips_to_the_whole_scan(tmp_path):
    """The JSON artifact the CI merge reads restores rows and their order."""
    corpus = _write_corpus(tmp_path)
    with gates.shipped_config():
        full = gates.scan_corpus_tasks(corpus, sample=1, jobs=1)
    artifact = tmp_path / "shard-0.json"
    gates.scan_shard(corpus, sample=1, jobs=1, shard=(0, 1), out=artifact)
    merged = gates.merge_shard_rows(tmp_path, corpus)
    assert merged == [row for _index, rows in full for row in rows]
