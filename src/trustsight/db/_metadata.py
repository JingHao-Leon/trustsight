"""Extracted from db.py: _metadata."""

from typing import Optional
from ._connection import get_connection

__all__ = ['OBSERVATION_SEQ_KEY', 'SEED_DIGEST_KEY', 'SEED_OBSERVATION_KEY', 'SEED_ORIGIN_KEY', 'SEED_OWNED_KEYS', 'SEED_VERSION_KEY', 'bump_observation_seq', 'get_metadata', 'observation_seq', 'seed_observation_count', 'set_metadata']

SEED_OBSERVATION_KEY = "seed_observation_count"

#: A monotonic counter advanced once per recorded observation (see
#: ``bump_observation_seq``).  Campaign and override TTLs are measured in
#: these units, not wall-clock: the tool must not consult a clock it does
#: not control (A11), and the database is instrument state, so B1
#: determinism holds.  Not part of ``config_fingerprint`` - a growing count
#: is not a different instrument.
OBSERVATION_SEQ_KEY = "observation_seq"

SEED_VERSION_KEY = "seed_version"

SEED_DIGEST_KEY = "seed_sha256"

SEED_ORIGIN_KEY = "seed_origin"

SEED_OWNED_KEYS = (SEED_OBSERVATION_KEY, SEED_VERSION_KEY)

def get_metadata(key: str) -> Optional[str]:
    """Return a metadata value by key, or None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

def set_metadata(key: str, value: str) -> None:
    """Set or overwrite a metadata key-value pair."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )
        conn.commit()

def seed_observation_count() -> int:
    """Bootstrap observation count supplied by an imported seed.

    A fresh install has no analysis history, so tier C novelty would be
    gated off entirely (see :func:`~trustsight.scoring.maturity`).  A
    seed asserts that the database already knows a large body of AUR
    source URLs, which is what maturity is really asking about.
    """
    raw = get_metadata(SEED_OBSERVATION_KEY)
    if raw is None:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def observation_seq() -> int:
    """The current observation counter, or 0 when nothing is recorded yet.

    A database without the metadata table (an uninitialised or read-only
    fixture) reads as 0 rather than raising: an unreadable clock means "no
    observations", which is the correct safe default for callers that only
    use it to decide whether a TTL has lapsed.
    """
    try:
        raw = get_metadata(OBSERVATION_SEQ_KEY)
    except Exception:  # noqa: BLE001 - no table means no observations yet
        return 0
    if raw is None:
        return 0
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def bump_observation_seq() -> int:
    """Advance the observation clock by one and return the new value.

    Called from ``insert_analysis`` inside the same transaction that writes
    the analysis row, so the clock and the recorded history cannot diverge:
    every observation the instrument can later consult has bumped it once.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (OBSERVATION_SEQ_KEY,)
        ).fetchone()
        try:
            current = max(0, int(row["value"])) if row else 0
        except (TypeError, ValueError):
            current = 0
        nxt = current + 1
        conn.execute(
            """INSERT INTO metadata (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (OBSERVATION_SEQ_KEY, str(nxt)),
        )
        conn.commit()
        return nxt
