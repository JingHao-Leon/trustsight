"""Tests for the operator watchlist loader."""

import json

from trustsight.watchlist import load_watchlist, watchlist_hashes


def test_absent_watchlist_is_empty(tmp_path):
    assert load_watchlist(tmp_path / "missing.json") == {}


def test_malformed_watchlist_is_empty(tmp_path):
    bad = tmp_path / "watchlist.json"
    bad.write_text("{not json")
    assert load_watchlist(bad) == {}


def test_entries_load_hashes_and_labels(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"version": 1, "entries": [
        {"name_hash": "aaa", "label": "orphan sweep"},
        {"name_hash": "bbb"},
        "garbage",
        {"label": "no hash"},
    ]}))
    assert load_watchlist(path) == {"aaa": "orphan sweep", "bbb": ""}
    assert watchlist_hashes(path) == {"aaa", "bbb"}
