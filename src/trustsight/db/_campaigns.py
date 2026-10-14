"""Campaign alert mode: a bounded, expiring state of heightened alert.

Borrowed from trained immunity: a strong stimulus (a corroborated campaign)
leaves the instrument temporarily primed for the packages it touched.  The
maladaptive version is chronic inflammation - a state that never expires -
so the whole design is about making expiry structural.

Time is measured in **observations**, not wall-clock.  The tool must not
consult a clock it does not control, and the observation counter is
instrument state, so a run is reproducible.  An expired campaign is simply
filtered out by :func:`active_campaigns`; there is nothing to sweep.
"""

from __future__ import annotations

import json
from typing import Optional

from ._connection import get_connection
from ._metadata import observation_seq

__all__ = [
    "activate_campaign",
    "active_campaigns",
    "all_campaigns",
    "expired_unannounced",
    "mark_expiry_announced",
]

#: Default lifetime, in observations.  Small on purpose: tens of recorded
#: analyses, not days.  A TTL measured in observations is what makes expiry
#: real rather than a policy someone forgets to enforce.
DEFAULT_TTL_OBSERVATIONS = 40


def _row_to_dict(row) -> dict:
    try:
        scope = json.loads(row["scope_json"] or "[]")
    except (TypeError, ValueError):
        scope = []
    return {
        "campaign_id": row["campaign_id"],
        "scope": [str(s) for s in scope],
        "source": row["source"] or "",
        "activated_at_obs": int(row["activated_at_obs"]),
        "ttl_obs": int(row["ttl_obs"]),
        "expires_at_obs": int(row["activated_at_obs"]) + int(row["ttl_obs"]),
        "expiry_announced": int(row["expiry_announced"] or 0),
    }


def all_campaigns() -> list[dict]:
    """Every recorded campaign, active or not (tests and diagnostics)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM campaign_alerts ORDER BY campaign_id"
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def active_campaigns(now_obs: Optional[int] = None) -> list[dict]:
    """Campaigns whose TTL has not lapsed at *now_obs*.

    Expiry is structural: a campaign past ``activated_at_obs + ttl_obs`` is
    never returned, so no code path can read an expired campaign and no
    sweep is needed to retire one.
    """
    now = observation_seq() if now_obs is None else int(now_obs)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM campaign_alerts WHERE activated_at_obs + ttl_obs > ?"
            " ORDER BY campaign_id",
            (now,),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def expired_unannounced(now_obs: Optional[int] = None) -> list[dict]:
    """Lapsed campaigns not yet reported as expired.

    Silence about a lapsed campaign is ambiguous between "no campaign" and
    "a campaign ended": the caller reports each once, the way an expired
    indicator is reported rather than dropped.
    """
    now = observation_seq() if now_obs is None else int(now_obs)
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM campaign_alerts"
            " WHERE activated_at_obs + ttl_obs <= ? AND expiry_announced = 0"
            " ORDER BY campaign_id",
            (now,),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def mark_expiry_announced(campaign_id: str) -> None:
    """Record that a lapsed campaign has been reported."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE campaign_alerts SET expiry_announced = 1 WHERE campaign_id = ?",
            (campaign_id,),
        )
        conn.commit()


def activate_campaign(
    campaign_id: str,
    scope,
    source: str = "",
    ttl_obs: int = DEFAULT_TTL_OBSERVATIONS,
    *,
    max_active: int = 0,
    now_obs: Optional[int] = None,
) -> bool:
    """Activate (or re-arm) a campaign, bounded by the active-campaign cap.

    A re-activation refreshes the window rather than stacking rows.  When
    the cap is reached, a new campaign evicts the oldest **lapsed** one;
    a live TTL is never shortened, so a full set of live campaigns simply
    refuses the newcomer.  Returns True when the campaign is active.
    """
    now = observation_seq() if now_obs is None else int(now_obs)
    ttl = max(1, int(ttl_obs))
    payload = json.dumps(sorted({str(s) for s in scope}), separators=(",", ":"))
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT * FROM campaign_alerts WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        if existing is not None:
            conn.execute(
                "UPDATE campaign_alerts SET scope_json = ?, source = ?,"
                " activated_at_obs = ?, ttl_obs = ?, expiry_announced = 0"
                " WHERE campaign_id = ?",
                (payload, source, now, ttl, campaign_id),
            )
            conn.commit()
            return True
        if max_active > 0:
            active = conn.execute(
                "SELECT campaign_id FROM campaign_alerts"
                " WHERE activated_at_obs + ttl_obs > ?",
                (now,),
            ).fetchall()
            if len(active) >= max_active:
                lapsed = conn.execute(
                    "SELECT campaign_id FROM campaign_alerts"
                    " WHERE activated_at_obs + ttl_obs <= ?"
                    " ORDER BY activated_at_obs LIMIT 1",
                    (now,),
                ).fetchone()
                if lapsed is None:
                    # Every slot holds a live TTL: refuse rather than evict.
                    return False
                conn.execute(
                    "DELETE FROM campaign_alerts WHERE campaign_id = ?",
                    (lapsed["campaign_id"],),
                )
        conn.execute(
            "INSERT INTO campaign_alerts"
            " (campaign_id, scope_json, source, activated_at_obs, ttl_obs,"
            "  expiry_announced) VALUES (?, ?, ?, ?, ?, 0)",
            (campaign_id, payload, source, now, ttl),
        )
        conn.commit()
        return True
