"""Extracted from db.py: _maintainers."""

import sqlite3
from typing import Optional
from ._connection import _get_salt, _hash_maintainer_value, get_connection

__all__ = ['get_maintainer_global_count', 'is_maintainer_globally_novel', 'lookup_maintainer']

def lookup_maintainer(name: str, email: str = "") -> Optional[dict]:
    """Look up a maintainer by salted hash of *name* and optional *email*.

    Returns the most relevant hashed row, or None when no salt has been
    configured (the database has never been seeded or migrated).
    """
    if not name:
        return None
    with get_connection() as conn:
        salt = _get_salt(conn)
        if not salt:
            return None
        name_hash = _hash_maintainer_value(name, salt)
        if email:
            email_hash = _hash_maintainer_value(email, salt)
            row = conn.execute(
                """SELECT * FROM maintainers_hashed
                   WHERE name_hash = ? OR email_hash = ?
                   ORDER BY package_count DESC LIMIT 1""",
                (name_hash, email_hash),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT * FROM maintainers_hashed
                   WHERE name_hash = ?
                   ORDER BY package_count DESC LIMIT 1""",
                (name_hash,),
            ).fetchone()
        return dict(row) if row else None

def is_maintainer_globally_novel(name: str) -> bool:
    """Return True if *name* has never been seen as a maintainer."""
    if not name:
        return True
    with get_connection() as conn:
        # Hashed corpus (v0.12.0+).
        salt = _get_salt(conn)
        if salt:
            name_hash = _hash_maintainer_value(name, salt)
            row = conn.execute(
                "SELECT 1 FROM maintainers_hashed WHERE name_hash = ?", (name_hash,)
            ).fetchone()
            if row:
                return False
            row = conn.execute(
                "SELECT 1 FROM package_maintainers_hashed WHERE name_hash = ?",
                (name_hash,),
            ).fetchone()
            if row:
                return False
        # Active legacy plaintext table (still present on unseeded databases).
        try:
            row = conn.execute(
                "SELECT 1 FROM maintainers WHERE name = ?", (name,)
            ).fetchone()
            if row:
                return False
        except sqlite3.OperationalError:
            pass
        # Renamed legacy backup, for databases that have been migrated.
        try:
            row = conn.execute(
                "SELECT 1 FROM maintainers_deprecated_backup WHERE name = ?", (name,)
            ).fetchone()
            if row:
                return False
        except sqlite3.OperationalError:
            pass
        # Legacy summary table still used by some tests and old seeds.
        try:
            seed_row = conn.execute(
                "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
            ).fetchone()
            if seed_row and seed_row["count"] > 0:
                return False
        except sqlite3.OperationalError:
            pass
    return True

def get_maintainer_global_count(name: str) -> int:
    """How many packages a maintainer is recorded against by the seed."""
    if not name:
        return 0
    with get_connection() as conn:
        salt = _get_salt(conn)
        if salt:
            name_hash = _hash_maintainer_value(name, salt)
            row = conn.execute(
                """SELECT SUM(package_count) AS total FROM maintainers_hashed
                   WHERE name_hash = ?""",
                (name_hash,),
            ).fetchone()
            total = int(row["total"] or 0) if row and row["total"] else 0
            row = conn.execute(
                """SELECT COUNT(DISTINCT package_id) AS n FROM package_maintainers_hashed
                   WHERE name_hash = ?""",
                (name_hash,),
            ).fetchone()
            total += int(row["n"] or 0) if row else 0
            return total
        try:
            row = conn.execute(
                "SELECT count FROM maintainer_counts WHERE name = ?", (name,)
            ).fetchone()
            return row["count"] if row else 0
        except sqlite3.OperationalError:
            return 0
