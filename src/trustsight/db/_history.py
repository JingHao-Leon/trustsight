"""Extracted from db.py: _history."""

from datetime import datetime, timezone
import hashlib
from typing import Optional
from ._connection import get_connection
from ._packages import _RESERVED_NAMES

__all__ = ['MAX_OBSERVED_DOMAINS', 'MAX_OBSERVED_KEYS', 'MAX_OBSERVED_LITERALS', 'MAX_PROPERTY_TRANSITIONS_PER_KEY', 'MAX_RECIPE_OBSERVATIONS_PER_PACKAGE', '_array_entries_hash', '_parse_ts', 'array_seen_before', 'correlation_feed', 'domain_first_seen', 'domain_seen_within', 'get_all_packages', 'get_history', 'get_pkgbuild_snapshot', 'get_property_transitions', 'key_observed_before', 'observed_domain_count', 'observed_key_count', 'package_added_literals', 'read_aur_cache', 'record_added_literals', 'record_observed_domain', 'record_observed_key', 'record_property_transition', 'record_recipe_document', 'save_pkgbuild_snapshot', 'tuple_observation_count', 'write_aur_cache']

def get_history(package_id: int, limit: int = 20, *, from_date: str | None = None, to_date: str | None = None) -> list[dict]:
    """Return recent analysis history for *package_id*, newest first.

    Args:
        package_id:  Foreign key into the packages table.
        limit:  Maximum rows returned; ``None`` means no limit.
        from_date:  Inclusive lower bound on the timestamp column
            (``YYYY-MM-DD`` or full ISO string).  Only rows at or after
            this date are returned.
        to_date:  Inclusive upper bound on the timestamp column.
            Only rows at or before this date are returned.
    """
    with get_connection() as conn:
        query = "SELECT * FROM analysis_history WHERE package_id = ?"
        params: list = [package_id]
        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)
        if to_date:
            # Add a day so '2026-06-01' includes entries on that date.
            query += " AND timestamp <= ?"
            params.append(to_date + "T23:59:59" if len(to_date) == 10 else to_date)
        query += " ORDER BY id DESC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def get_property_transitions(
    package_name: str, *, property_key: str | None = None, limit: int | None = 500
) -> list[dict]:
    """Return recorded property-value transitions for *package_name*.

    Ordered by property key, oldest first within a key, so each key's rows
    read as a timeline.  *limit* bounds the newest rows returned (``None``
    means no bound); the write path already caps rows per key.  An unknown
    package yields an empty list.
    """
    with get_connection() as conn:
        where = "WHERE package_name = ?"
        params: list = [package_name]
        if property_key:
            where += " AND property_key = ?"
            params.append(property_key)
        if limit:
            # Newest rows overall, then ordered for display.
            query = (
                f"SELECT * FROM (SELECT * FROM property_transitions {where} "
                f"ORDER BY id DESC LIMIT ?) ORDER BY property_key, id"
            )
            params.append(limit)
        else:
            query = (
                f"SELECT * FROM property_transitions {where} "
                f"ORDER BY property_key, id"
            )
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

def get_all_packages() -> list[dict]:
    """Return every package row excluding internal sentinels, ordered by name."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM packages WHERE name NOT IN ('__seed__') ORDER BY name",
        ).fetchall()
        return [dict(r) for r in rows]

def read_aur_cache(names: list[str], ttl_minutes: int = 60) -> dict[str, dict]:
    """Return cached AUR responses for *names* that are still fresh.

    Returns ``{name: {"version": str, "last_modified": int}}`` for cache
    hits younger than *ttl_minutes*.  Expired entries are deleted inline.
    """
    if not names:
        return {}
    with get_connection() as conn:
        placeholders = ",".join("?" for _ in names)
        rows = conn.execute(
            f"""SELECT name, version, last_modified, cached_at
                FROM aur_cache
                WHERE name IN ({placeholders})""",
            names,
        ).fetchall()
        hits = {}
        expired = []
        for r in rows:
            age = (datetime.now(timezone.utc) - _parse_ts(r["cached_at"])).total_seconds() / 60
            if age < ttl_minutes:
                hits[r["name"]] = {
                    "version": r["version"],
                    "last_modified": r["last_modified"],
                }
            else:
                expired.append(r["name"])
        if expired:
            placeholders = ",".join("?" for _ in expired)
            conn.execute(
                f"DELETE FROM aur_cache WHERE name IN ({placeholders})", expired
            )
            conn.commit()
    return hits

def write_aur_cache(entries: dict[str, tuple[str, int | None]]) -> None:
    """Insert or update the AUR cache for *entries*.

    *entries* maps ``name -> (version, last_modified)`` where
    *last_modified* is an integer Unix timestamp or None.
    """
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO aur_cache (name, version, last_modified, cached_at)
               VALUES (?, ?, ?, datetime('now'))
               ON CONFLICT(name) DO UPDATE SET
                   version = excluded.version,
                   last_modified = excluded.last_modified,
                   cached_at = excluded.cached_at""",
            [(name, ver, lm) for name, (ver, lm) in entries.items()],
        )
        conn.commit()

def _parse_ts(ts: str | None) -> datetime:
    """Parse a SQLite datetime string, defaulting to epoch on garbage."""
    if not ts:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return datetime.fromtimestamp(0, tz=timezone.utc)

def get_pkgbuild_snapshot(package_name: str) -> Optional[dict]:
    """Return the PKGBUILD snapshot for *package_name*, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM pkgbuild_snapshots WHERE package_name = ?",
            (package_name,),
        ).fetchone()
        return dict(row) if row else None

def save_pkgbuild_snapshot(
    package_name: str,
    pkgbuild_text: str,
    version: str,
    last_modified: int = 0,
    srcinfo_text: Optional[str] = None,
    install_text: Optional[str] = None,
) -> None:
    """Insert or update the PKGBUILD snapshot for *package_name*."""
    # Same guard as upsert_package.  These two tables are keyed by
    # package_name directly rather than through packages(id), so they were
    # the way round the reserved-name check: a baseline artifact, or an
    # AUR package actually named __seed__, could write a row under a name
    # the rest of the code treats as internal.
    if package_name in _RESERVED_NAMES or package_name.startswith("__"):
        raise ValueError(f"reserved package name: {package_name!r}")
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO pkgbuild_snapshots
               (package_name, pkgbuild_text, srcinfo_text, install_text,
                version, last_modified, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(package_name) DO UPDATE SET
                   pkgbuild_text = excluded.pkgbuild_text,
                   srcinfo_text = excluded.srcinfo_text,
                   install_text = excluded.install_text,
                   version = excluded.version,
                   last_modified = excluded.last_modified,
                   captured_at = excluded.captured_at""",
            (package_name, pkgbuild_text, srcinfo_text, install_text,
             version, last_modified),
        )
        conn.commit()

MAX_RECIPE_OBSERVATIONS_PER_PACKAGE = 128

MAX_PROPERTY_TRANSITIONS_PER_KEY = 256

def _array_entries_hash(entries) -> str:
    import json as _json

    payload = _json.dumps(
        [str(entry) for entry in entries], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()

def record_recipe_document(
    package_name: str,
    scalars: dict,
    arrays: dict,
    observed_at: Optional[str] = None,
) -> None:
    """Store one observed RecipeDoc's scalars and arrays.

    Not the full text: the index exists for exact tuple history, and a
    stored PKGBUILD would be another unbounded attacker-authored payload.
    """
    if package_name in _RESERVED_NAMES or package_name.startswith("__"):
        raise ValueError(f"reserved package name: {package_name!r}")
    import json as _json

    scalars_json = _json.dumps(
        {str(k): str(v) for k, v in scalars.items()},
        separators=(",", ":"), sort_keys=True)
    with get_connection() as conn:
        if observed_at is None:
            conn.execute(
                """INSERT OR REPLACE INTO recipe_observations
                   (package_name, observed_at, scalars_json)
                   VALUES (?, datetime('now'), ?)""",
                (package_name, scalars_json),
            )
            observed_at = conn.execute(
                "SELECT observed_at FROM recipe_observations "
                "WHERE package_name = ? ORDER BY observed_at DESC LIMIT 1",
                (package_name,),
            ).fetchone()["observed_at"]
        else:
            conn.execute(
                """INSERT OR REPLACE INTO recipe_observations
                   (package_name, observed_at, scalars_json)
                   VALUES (?, ?, ?)""",
                (package_name, observed_at, scalars_json),
            )
        for name, entries in arrays.items():
            conn.execute(
                """INSERT INTO recipe_array_observations
                   (package_name, array_name, entries_hash, observed_at)
                   VALUES (?, ?, ?, ?)""",
                (package_name, str(name), _array_entries_hash(entries),
                 observed_at),
            )
        conn.execute(
            """DELETE FROM recipe_array_observations
               WHERE package_name = ? AND observed_at NOT IN (
                   SELECT observed_at FROM recipe_observations
                   WHERE package_name = ?
                   ORDER BY observed_at DESC LIMIT ?)""",
            (package_name, package_name, MAX_RECIPE_OBSERVATIONS_PER_PACKAGE),
        )
        conn.execute(
            """DELETE FROM recipe_observations
               WHERE package_name = ? AND observed_at NOT IN (
                   SELECT observed_at FROM recipe_observations
                   WHERE package_name = ?
                   ORDER BY observed_at DESC LIMIT ?)""",
            (package_name, package_name, MAX_RECIPE_OBSERVATIONS_PER_PACKAGE),
        )
        conn.commit()

def array_seen_before(package_name: str, array_name: str, entries) -> bool:
    """True when this exact array tuple was observed before."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT 1 FROM recipe_array_observations
               WHERE package_name = ? AND array_name = ? AND entries_hash = ?
               LIMIT 1""",
            (package_name, array_name, _array_entries_hash(entries)),
        ).fetchone()
    return row is not None

def tuple_observation_count(package_name: str, array_name: str,
                            entries) -> int:
    """How many distinct observations held this exact array tuple."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT COUNT(DISTINCT observed_at) FROM recipe_array_observations
               WHERE package_name = ? AND array_name = ? AND entries_hash = ?""",
            (package_name, array_name, _array_entries_hash(entries)),
        ).fetchone()
    return int(row[0] or 0)

MAX_OBSERVED_KEYS = 50_000

MAX_OBSERVED_DOMAINS = 20_000

def record_observed_key(key: str, observed_at: Optional[str] = None) -> None:
    """Record a signing key as observed in the ecosystem."""
    key = (key or "").strip()[:512]
    if not key:
        return
    with get_connection() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO observed_signing_keys(key, first_seen)
               VALUES (?, COALESCE(?, datetime('now')))""",
            (key, observed_at),
        )
        # ponytail: the prune is O(n) per insert (a corpus-bootstrap path,
        # not per-diff); switch to a periodic-trigger prune if a ledger at
        # the cap makes bootstrap slow.
        conn.execute(
            """DELETE FROM observed_signing_keys WHERE key IN (
                   SELECT key FROM observed_signing_keys
                   ORDER BY first_seen DESC LIMIT -1 OFFSET ?)""",
            (MAX_OBSERVED_KEYS,),
        )
        conn.commit()

def key_observed_before(key: str) -> bool:
    """True when *key* has been observed in the ecosystem index."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM observed_signing_keys WHERE key = ? LIMIT 1",
            ((key or "").strip()[:512],),
        ).fetchone()
    return row is not None

def observed_key_count() -> int:
    with get_connection() as conn:
        return int(conn.execute(
            "SELECT COUNT(*) FROM observed_signing_keys").fetchone()[0] or 0)

def record_observed_domain(domain: str, observed_at: Optional[str] = None) -> None:
    """Record a maintainer email domain as observed in the ecosystem."""
    domain = (domain or "").strip().lower()[:253]
    if not domain:
        return
    with get_connection() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO observed_maintainer_domains(
                   domain, first_seen)
               VALUES (?, COALESCE(?, datetime('now')))""",
            (domain, observed_at),
        )
        conn.execute(
            """DELETE FROM observed_maintainer_domains WHERE domain IN (
                   SELECT domain FROM observed_maintainer_domains
                   ORDER BY first_seen DESC LIMIT -1 OFFSET ?)""",
            (MAX_OBSERVED_DOMAINS,),
        )
        conn.commit()

def domain_first_seen(domain: str) -> Optional[str]:
    """The first-seen stamp for *domain*, or None if never observed."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT first_seen FROM observed_maintainer_domains WHERE domain = ?",
            ((domain or "").strip().lower()[:253],),
        ).fetchone()
    return row[0] if row else None

def domain_seen_within(domain: str, days: int) -> bool:
    """True when *domain* was first observed within the last *days* days.

T002's window, not merely "never observed". A domain
    first seen this week is as novel an adoption signal as one never seen at
    all; only the observation window distinguishes them.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT first_seen >= datetime('now', ?) "
            "FROM observed_maintainer_domains WHERE domain = ?",
            (f"-{int(days)} days", (domain or "").strip().lower()[:253]),
        ).fetchone()
    return bool(row and row[0])

def observed_domain_count() -> int:
    with get_connection() as conn:
        return int(conn.execute(
            "SELECT COUNT(*) FROM observed_maintainer_domains").fetchone()[0] or 0)

MAX_OBSERVED_LITERALS = 50_000

def record_added_literals(package_name: str, literals, observed_at=None) -> None:
    """Record a package's added encoded literals."""
    package_name = (package_name or "").strip()
    if not package_name or not literals:
        return
    with get_connection() as conn:
        for literal in literals:
            text = str(literal)[:4096]
            if not text:
                continue
            conn.execute(
                """INSERT INTO observed_added_literals(
                       package_name, literal, literal_len, observed_at)
                   VALUES (?, ?, ?, COALESCE(?, datetime('now')))""",
                (package_name, text, len(text), observed_at),
            )
        conn.execute(
            """DELETE FROM observed_added_literals WHERE rowid IN (
                   SELECT rowid FROM observed_added_literals
                   ORDER BY observed_at DESC LIMIT -1 OFFSET ?)""",
            (MAX_OBSERVED_LITERALS,),
        )
        conn.commit()

def package_added_literals(package_name: str) -> list[tuple[str, int]]:
    """``(literal, length)`` for one package's recorded added literals."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT literal, literal_len FROM observed_added_literals
               WHERE package_name = ? ORDER BY observed_at DESC LIMIT 200""",
            ((package_name or "").strip(),),
        ).fetchall()
    return [(r[0], int(r[1])) for r in rows]

def record_property_transition(
    package_name: str, property_key: str,
    old_value, new_value, observed_at: Optional[str] = None,
) -> None:
    """Append one property-value transition.

    The same row shape ``full_aur.properties`` writes; exposed so the corpus
    sweep can record a maintainer transition and the ``adoption_events`` view
    can serve G003 without re-deriving it per package.  Values are stored as
    JSON so ``json_extract`` reads them back.
    """
    import json as _json

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO property_transitions "
            "(package_name, property_key, old_value, new_value, observed_at) "
            "VALUES (?, ?, ?, ?, COALESCE(?, datetime('now')))",
            (package_name, property_key, _json.dumps(old_value),
             _json.dumps(new_value), observed_at),
        )
        conn.execute(
            "DELETE FROM property_transitions WHERE package_name=? AND "
            "property_key=? AND id NOT IN ("
            "SELECT id FROM property_transitions WHERE package_name=? AND "
            "property_key=? ORDER BY id DESC LIMIT ?)",
            (package_name, property_key, package_name, property_key,
             MAX_PROPERTY_TRANSITIONS_PER_KEY),
        )
        conn.commit()

def correlation_feed(package_names) -> dict[str, dict]:
    """Per-package G-series inputs, read from the views.

    ``{package: {hosts_gained, added_literals, maintainer,
    adoption_predicates}}``.  One pass over each view instead of a query per
    package, so correlation is O(cycle).
    """
    names = {str(n) for n in package_names if n}
    out = {
        name: {"hosts_gained": [], "added_literals": [],
               "maintainer": "", "adoption_predicates": []}
        for name in names
    }
    if not names:
        return out
    with get_connection() as conn:
        for row in conn.execute(
                "SELECT package_name, host FROM gained_hosts_window"):
            if row[0] in out:
                out[row[0]]["hosts_gained"].append(row[1])
        for row in conn.execute(
                "SELECT package_name, literal FROM added_literal_hashes"):
            if row[0] in out:
                out[row[0]]["added_literals"].append(row[1])
        for row in conn.execute(
                "SELECT package_name, maintainer, predicate "
                "FROM adoption_events ORDER BY observed_at"):
            if row[0] in out:
                out[row[0]]["maintainer"] = row[1]
                if row[2] not in out[row[0]]["adoption_predicates"]:
                    out[row[0]]["adoption_predicates"].append(row[2])
    return out
