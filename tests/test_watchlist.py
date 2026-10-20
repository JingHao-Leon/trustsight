"""Tests for the operator watchlist loader."""

import json

from trustsight.watchlist import (
    add_entry,
    add_package,
    load_packages,
    load_watchlist,
    watchlist_hashes,
)


def test_absent_watchlist_is_empty(tmp_path):
    assert load_watchlist(tmp_path / "missing.json") == {}
    assert load_packages(tmp_path / "missing.json") == {}


def test_malformed_watchlist_is_empty(tmp_path):
    bad = tmp_path / "watchlist.json"
    bad.write_text("{not json")
    assert load_watchlist(bad) == {}
    assert load_packages(bad) == {}


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


def test_packages_load_names_and_labels(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"version": 1, "packages": {
        " xsp ": "review",
        "": "no name",
        "empty": None,
    }}))
    assert load_packages(path) == {"xsp": "review", "empty": ""}


def test_a_malformed_packages_section_is_empty(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"version": 1, "packages": ["xsp"]}))
    assert load_packages(path) == {}


def test_add_package_needs_no_database_and_keeps_entries(tmp_path):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"version": 1, "entries": [
        {"name_hash": "aaa", "label": "orphan sweep"},
    ]}))

    assert add_package("xsp", "review", path) == "xsp"
    assert add_package("xsp", "ignored", path) == "xsp"

    data = json.loads(path.read_text())
    assert data["packages"] == {"xsp": "review"}
    assert data["entries"] == [{"name_hash": "aaa", "label": "orphan sweep"}]


def test_add_entry_keeps_packages(tmp_path, monkeypatch):
    path = tmp_path / "watchlist.json"
    path.write_text(json.dumps({"version": 1, "packages": {"xsp": "review"}}))
    monkeypatch.setattr("trustsight.watchlist.local_hash", lambda n: "h1")

    add_entry("fennekuiper", "orphan sweep", path)

    data = json.loads(path.read_text())
    assert data["packages"] == {"xsp": "review"}
    assert data["entries"] == [{"name_hash": "h1", "label": "orphan sweep"}]
