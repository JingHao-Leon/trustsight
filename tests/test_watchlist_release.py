"""Tests for the imported (signed) watchlist release."""

import json

import pytest

from trustsight import config
from trustsight import db as db_module
from trustsight.watchlist import (
    import_release,
    load_packages,
    load_release_maintainers,
    load_release_packages,
    load_watchlist,
)

SALT_A = "a" * 64
SALT_B = "b" * 64
HASH = "f" * 64


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    data = tmp_path / "data"
    conf = tmp_path / "config"
    data.mkdir()
    conf.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "CONFIG_DIR", conf)
    monkeypatch.setattr(db_module, "DATA_DIR", data)
    db_module.init_db()
    return tmp_path


def _release(**overrides):
    doc = {
        "schema_version": 1,
        "source": "emiliano-go",
        "salt": SALT_A,
        "packages": {"xsp": "thread"},
        "maintainers": {HASH: "banned account"},
    }
    doc.update(overrides)
    return doc


def _stored_salt() -> str | None:
    from trustsight.db import get_connection
    from trustsight.db._connection import _get_salt

    with get_connection() as conn:
        return _get_salt(conn)


def test_import_stores_packages_and_hashes_and_adopts_salt(isolated):
    stats = import_release(_release())

    assert stats == {
        "source": "emiliano-go",
        "packages_imported": 1,
        "maintainers_imported": 1,
        "maintainers_skipped": 0,
        "salt_adopted": True,
    }
    assert load_release_packages() == {"xsp": "thread"}
    assert load_release_maintainers() == {HASH: "banned account"}
    assert _stored_salt() == SALT_A


def test_import_skips_hashes_when_a_different_salt_is_stored(isolated):
    from trustsight.db import get_connection
    from trustsight.db._connection import SEED_META_SALT_KEY

    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO seed_meta (key, value) VALUES (?, ?)",
            (SEED_META_SALT_KEY, SALT_B),
        )
        conn.commit()

    stats = import_release(_release())

    assert stats["maintainers_imported"] == 0
    assert stats["maintainers_skipped"] == 1
    assert stats["salt_adopted"] is False
    assert _stored_salt() == SALT_B
    assert load_release_maintainers() == {}
    assert load_release_packages() == {"xsp": "thread"}


def test_import_is_idempotent_per_source(isolated):
    import_release(_release())
    import_release(_release(packages={"xsp": "updated"}))

    assert load_release_packages() == {"xsp": "updated"}
    assert load_release_maintainers() == {HASH: "banned account"}


def test_local_entry_wins_and_imported_is_unioned(isolated):
    local = isolated / "config" / "watchlist.json"
    local.write_text(json.dumps({
        "version": 1,
        "packages": {"xsp": "operator"},
        "entries": [{"name_hash": HASH, "label": "operator"}],
    }))
    import_release(_release())

    assert load_packages() == {"xsp": "operator"}
    assert load_watchlist()[HASH] == "operator"
