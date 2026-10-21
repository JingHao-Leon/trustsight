"""The document cache.

``from_dict(to_dict(doc))`` must project identically for every projection,
and a cache entry must never become an authority: a version change, a
tokenizer change, or a corrupt payload is a miss that re-parses.
"""

import json
import pathlib

from trustsight.diffdoc import (
    DIFFDOC_SCHEMA_VERSION,
    DiffDoc,
    parse_diff,
    tokenizer_version,
)
from trustsight import doc_cache
from trustsight.doc_cache import (
    document_key,
    parse_diff_cached,
    parse_recipe_cached,
)
from trustsight.recipedoc import RecipeDoc, parse_recipe

_CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"

_PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
depends=('glibc' 'zlib')
source=('https://example.invalid/demo-1.0.tar.gz')
sha256sums=('abc')
build() {
  cd "$srcdir/demo-$pkgver"
  make
}
"""


def _sample_corpus(count=100):
    paths = sorted(_CORPUS.glob("*.diff"))
    step = max(1, len(paths) // count)
    return paths[::step][:count]


def _projections(doc: DiffDoc) -> dict:
    return {
        "files": doc.files,
        "lines": doc.lines,
        "line_map": doc.line_map(),
        "post_lines": doc.post_lines(),
        "pre_lines": doc.pre_lines(),
        "post_origins": doc.post_origins(),
        "pre_origins": doc.pre_origins(),
        "added": [line.index for line in doc.added_lines()],
        "removed": [line.index for line in doc.removed_lines()],
        "post_text": doc.post_text(),
        "pre_text": doc.pre_text(),
        "cut_hunks": doc.cut_hunks(),
    }


def test_diff_round_trip_projects_identically_over_the_corpus():
    for path in _sample_corpus():
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = parse_diff(text)
        rebuilt = DiffDoc.from_dict(doc.to_dict())
        assert rebuilt is not None, path.name
        assert rebuilt == doc, path.name
        assert _projections(rebuilt) == _projections(doc), path.name


def test_recipe_round_trip_projects_identically():
    recipe = parse_recipe(_PKGBUILD, file="PKGBUILD")
    rebuilt = RecipeDoc.from_dict(recipe.to_dict())
    assert rebuilt == recipe
    assert rebuilt.to_dict() == recipe.to_dict()


def _findings(fact):
    return [
        (e.rule_id, e.severity, e.weight, e.params or {})
        for e in fact.score_breakdown
    ]


def test_findings_are_identical_cold_and_from_cache():
    """Replay equality: findings from a cached document are
    byte-identical to findings from a fresh parse.  The parse cache is the
    in-process memo (`_parse_diff_lines_cached`); the cross-process document
    cache is exercised by `tests/harness/diffdoc_parity.py`."""
    from trustsight.analysis.pipeline import scan_diff
    from trustsight.diffdoc import _parse_diff_lines_cached

    for path in _sample_corpus(20):
        text = path.read_text(encoding="utf-8", errors="replace")
        _parse_diff_lines_cached.cache_clear()
        cold = scan_diff(text, package_name=path.stem)
        warm = scan_diff(text, package_name=path.stem)
        assert _findings(cold) == _findings(warm), path.name


def test_a_version_mismatch_is_a_miss_not_a_partial_read():
    doc = parse_diff("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n")
    payload = doc.to_dict()
    payload["schema_version"] = DIFFDOC_SCHEMA_VERSION + 1
    assert DiffDoc.from_dict(payload) is None
    payload["schema_version"] = DIFFDOC_SCHEMA_VERSION
    payload["tokenizer_version"] = "not-the-parser"
    assert DiffDoc.from_dict(payload) is None
    assert DiffDoc.from_dict({"files": []}) is None


def test_cached_parse_matches_a_fresh_parse_and_survives_a_corrupt_entry(tmp_path):
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n"
    fresh = parse_diff(text)
    first = parse_diff_cached(text, directory=tmp_path)
    assert first == fresh
    entry = tmp_path / f"diff-{document_key(text)}.json"
    assert entry.exists()
    assert entry.stat().st_size <= doc_cache.MAX_DOC_CACHE_BYTES
    # A valid entry is served.
    assert parse_diff_cached(text, directory=tmp_path) == fresh
    # A corrupt entry falls back to a fresh parse rather than raising.
    entry.write_text("{not json", encoding="utf-8")
    assert parse_diff_cached(text, directory=tmp_path) == fresh
    # An old-schema entry is a miss too.
    entry.write_text(json.dumps({"schema_version": 0, "files": [], "lines": []}))
    assert parse_diff_cached(text, directory=tmp_path) == fresh


def test_cached_recipe_matches_a_fresh_parse(tmp_path):
    fresh = parse_recipe(_PKGBUILD, file="PKGBUILD")
    assert parse_recipe_cached(_PKGBUILD, file="PKGBUILD", directory=tmp_path) == fresh
    assert parse_recipe_cached(_PKGBUILD, file="PKGBUILD", directory=tmp_path) == fresh


def test_the_tokenizer_digest_is_available():
    assert tokenizer_version() != ""


def test_an_oversized_cache_entry_is_a_miss_without_reading_it(
        tmp_path, monkeypatch):
    """A cache file is not allowed to decide the read's allocation (A4/A14).

    The size is refused from the stat before the file is opened, and the
    caller falls back to parsing the real text.
    """
    import tracemalloc

    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n"
    monkeypatch.setattr(doc_cache, "MAX_DOC_CACHE_BYTES", 1024)
    entry = tmp_path / f"diff-{document_key(text)}.json"
    entry.write_bytes(b"x" * (2 * 1024 * 1024))

    tracemalloc.start()
    try:
        assert doc_cache._load(entry, DiffDoc.from_dict) is None
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 256 * 1024, f"the oversized entry was materialised: {peak} bytes"
    assert parse_diff_cached(text, directory=tmp_path) == parse_diff(text)


def test_a_truncated_or_non_utf8_cache_entry_falls_back(tmp_path):
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n"
    fresh = parse_diff(text)
    entry = tmp_path / f"diff-{document_key(text)}.json"

    entry.write_text('{"files": [', encoding="utf-8")
    assert parse_diff_cached(text, directory=tmp_path) == fresh

    entry.write_bytes(b"\xff\xfe\x00")
    assert parse_diff_cached(text, directory=tmp_path) == fresh


def test_an_oversized_cache_payload_is_not_stored(tmp_path, monkeypatch):
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n"
    fresh = parse_diff(text)
    monkeypatch.setattr(doc_cache, "MAX_DOC_CACHE_BYTES", 16)
    assert parse_diff_cached(text, directory=tmp_path) == fresh
    entry = tmp_path / f"diff-{document_key(text)}.json"
    assert not entry.exists()
    # The missed store is not an error: the next call still parses and returns.
    assert parse_diff_cached(text, directory=tmp_path) == fresh
