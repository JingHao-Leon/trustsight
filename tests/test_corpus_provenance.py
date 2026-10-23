"""The provenance screen must reject packages, hashes, domains and patterns."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import corpus_provenance as prov  # noqa: E402


def _data(tmp_path):
    (tmp_path / "aur-compromised" / "wave").mkdir(parents=True)
    (tmp_path / "aur-compromised" / "wave" / "packages.tsv").write_text(
        "package\twaves\nbad-pkg\twave1\n")
    (tmp_path / "aur-compromised" / "wave" / "spam-packages.tsv").write_text(
        "name\tincident\tclassification\tmalicious_commit\tsource\n"
        "spam-pkg\tinc\tspam\t" + "a" * 40 + "\taur\n")
    (tmp_path / "iocs").mkdir()
    (tmp_path / "iocs" / "one.json").write_text(json.dumps([
        {"type": "domain", "value": "evil.example"},
        {"type": "hash", "value": "b" * 64},
        {"type": "package", "value": "ioc-pkg"},
        {"type": "pkgbuild_pattern", "value": "curl\\s+evil"},
    ]))
    (tmp_path / "watchlist").mkdir()
    (tmp_path / "watchlist" / "official.json").write_text(json.dumps(
        {"packages": {"watched": "note"}, "maintainers": {}, "salt": "x"}))
    return tmp_path


def test_package_and_commit_screen(tmp_path):
    indicators = prov.load_indicators(_data(tmp_path))
    assert prov.package_excluded("bad-pkg", indicators)
    assert prov.package_excluded("ioc-pkg", indicators)
    assert prov.package_excluded("watched", indicators)
    assert prov.commit_excluded("a" * 40, indicators)
    assert prov.package_excluded("clean-pkg", indicators) is None


def test_text_screen_finds_domain_hash_and_pattern(tmp_path):
    indicators = prov.load_indicators(_data(tmp_path))
    hits = prov.text_excluded(
        "source=(https://evil.example/x.tar.gz)\n"
        f"sha256sums=('{'b' * 64}')\n"
        "curl evil\n",
        indicators,
    )
    assert any("domain" in hit for hit in hits)
    assert any("hash" in hit for hit in hits)
    assert any("pattern" in hit for hit in hits)


def test_lock_and_corpus_reports_record_counts(tmp_path):
    indicators = prov.load_indicators(_data(tmp_path))
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"entries": [
        {"pkg": "bad-pkg", "stratum": "s", "old_sha": "0" * 40, "new_sha": "1" * 40},
        {"pkg": "clean", "stratum": "s", "old_sha": "2" * 40, "new_sha": "3" * 40},
    ]}))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "clean__2..3.diff").write_text("+source=(https://evil.example/x)\n")
    report = prov.screen_lock(lock, indicators)
    assert report["excluded_of"] == "1 of 2 candidates"
    report = prov.screen_corpus(corpus, indicators)
    assert report["excluded_of"] == "1 of 1 diffs"
