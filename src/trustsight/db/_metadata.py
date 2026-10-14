"""Extracted from db.py: _metadata."""

from typing import Optional
from ._connection import get_connection

__all__ = ['SEED_DIGEST_KEY', 'SEED_OBSERVATION_KEY', 'SEED_ORIGIN_KEY', 'SEED_OWNED_KEYS', 'SEED_VERSION_KEY', 'get_metadata', 'seed_observation_count', 'set_metadata']

SEED_OBSERVATION_KEY = "seed_observation_count"

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
