"""Shape drift is measured against the committed lock, not guessed."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import corpus_shape_drift as drift  # noqa: E402


def test_shape_drift_reports_a_moved_stratum(tmp_path, monkeypatch):
    lock = {
        "entries": [
            {"pkg": "a", "stratum": "bin_repack"},
            {"pkg": "b", "stratum": "bin_repack"},
        ]
    }
    manifest = tmp_path / "corpus.lock"
    manifest.write_text(json.dumps(lock))
    strata = tmp_path / "strata.toml"
    strata.write_text("""
[strata.bin_repack]
target = 2
[strata.data_fonts]
target = 1
""")
    monkeypatch.setattr(drift.build_corpus, "fetch_meta", lambda force=False: [
        {"Name": "a-bin"}, {"Name": "b-bin"}, {"Name": "c-bin"},
    ])
    monkeypatch.setattr(drift.corpus_select, "EXISTING", ("bin_repack", "data_fonts"))
    monkeypatch.setattr(drift.corpus_select, "NEW", ())
    monkeypatch.setattr(drift.corpus_select, "metadata_match",
                        lambda pkg, stratum: stratum == "bin_repack")
    monkeypatch.setattr(sys, "argv", [
        "corpus_shape_drift.py", "--manifest", str(manifest),
        "--strata", str(strata), "--tolerance", "0.10",
    ])
    assert drift.main() == 0
