"""Extracted from db.py: _contacts.

The Contact Ledger (spec: contact-ledger): an append-only, cycle-versioned
record of every "stranger" a package introduces to the corpus.  Weight-0,
warm-only state, never a rule: entries never enter the score, and a
correction is a new entry rather than a rewrite, because the ledger's whole
value is that it was recorded then, with that information.
"""

from ._connection import get_connection

__all__ = [
    "contact_entries",
    "contact_ledger_available",
    "contact_ledger_size",
    "contacts_for_values",
    "first_seen_hosts_since",
    "host_first_seen",
    "record_contact",
    "record_host",
]


def contact_ledger_available() -> bool:
    """True when the ledger table exists (an absent/cold DB has none)."""
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='contact_ledger'").fetchone()
    except Exception:
        return False
    return row is not None


def record_host(host: str, first_seen: str) -> bool:
    """Record *host* as first seen at *first_seen*.  True when it is new."""
    host = (host or "").strip()
    if not host:
        return False
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO observed_hosts (host, first_seen) "
            "VALUES (?, ?)", (host, first_seen))
        conn.commit()
        return cur.rowcount == 1


def host_first_seen(host: str):
    """The ISO stamp a canonical host was first seen, or None."""
    host = (host or "").strip()
    if not host:
        return None
    with get_connection() as conn:
        row = conn.execute(
            "SELECT first_seen FROM observed_hosts WHERE host = ?",
            (host,)).fetchone()
    return row[0] if row else None


def first_seen_hosts_since(since_iso: str) -> set:
    """Hosts whose first_seen stamp is at or after *since_iso*."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT host FROM observed_hosts WHERE first_seen >= ?",
            (since_iso,)).fetchall()
    return {row[0] for row in rows}


def record_contact(package_name: str, kind: str, value: str, cycle_time: int,
                   observed_at: str, maintainer: str = "") -> bool:
    """Append one first-contact entry.  True when it is new to the ledger."""
    package_name = (package_name or "").strip()
    value = (value or "").strip()
    if not package_name or not value:
        return False
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO contact_ledger "
            "(package_name, kind, value, maintainer, cycle_time, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (package_name, kind, value, maintainer, int(cycle_time),
             observed_at))
        conn.commit()
        return cur.rowcount == 1


def contact_entries(cycle_time=None, package_name=None) -> list:
    """Ledger entries, newest cycle first, then kind and value."""
    query = ("SELECT package_name, kind, value, maintainer, cycle_time, "
             "observed_at FROM contact_ledger")
    clauses: list[str] = []
    params: list = []
    if cycle_time is not None:
        clauses.append("cycle_time = ?")
        params.append(int(cycle_time))
    if package_name is not None:
        clauses.append("package_name = ?")
        params.append(package_name)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY cycle_time DESC, kind ASC, value ASC"
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def contacts_for_values(kind: str, values) -> dict:
    """For *kind*, which of *values* already have a ledger entry.

    Returns ``{value: first_seen_utc}`` for those present, so a caller can
    tell a ``matched`` contact from a first ``ledger`` one without a query
    per value.
    """
    vals = [str(v) for v in values if v]
    if not vals:
        return {}
    placeholders = ",".join("?" * len(vals))
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT value, MIN(observed_at) FROM contact_ledger "
            f"WHERE kind = ? AND value IN ({placeholders}) GROUP BY value",
            [kind, *vals]).fetchall()
    return {row[0]: row[1] for row in rows}


def contact_ledger_size() -> int:
    """How many first-contact entries the ledger holds."""
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM contact_ledger").fetchone()
    return int(row[0] or 0)
