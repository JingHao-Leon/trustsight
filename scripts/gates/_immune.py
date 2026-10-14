"""Gates for the immune-import mechanisms: campaign state, elevation and
licensed escalation.

Each invariant here is about *instrument state* that must behave
deterministically: a campaign that expires by construction, a bonus that is
attributable, an elevation that names its campaign, and an escalation that
amplifies one notch and never authorizes.
"""

from __future__ import annotations

import contextlib
import pathlib
import tempfile

from scripts.gates._core import Gate

__all__ = [
    "gate_campaign_state_is_instrument_state",
    "gate_campaign_expiry_is_structural",
    "gate_campaign_points_are_attributed",
    "gate_elevation_is_attributed",
    "gate_escalation_is_one_notch",
    "gate_escalation_never_reaches_fatal",
    "gate_escalation_chains_are_rejected",
    "gate_expired_overrides_are_reported",
]


@contextlib.contextmanager
def _temp_db():
    """Run a block against a fresh, isolated database, then restore."""
    import trustsight.db as db

    old = db.DATA_DIR
    root = pathlib.Path(tempfile.mkdtemp(prefix="trustsight-gate-db-"))
    db.DATA_DIR = root
    try:
        db.init_db()
        yield db
    finally:
        db.DATA_DIR = old
        try:
            db.close_connections()
        except Exception:  # noqa: BLE001
            pass


def gate_campaign_state_is_instrument_state() -> Gate:
    """A campaign changes what the tool knows, not what the tool is.

    Campaign state lives in the database, never in the config fingerprint:
    two machines with the same configuration and the same observations stay
    in step regardless of which campaigns are armed.  Asserted structurally
    (the fingerprint material names no campaign/observation field) so it
    cannot drift when the fingerprint is edited.
    """
    import inspect

    from trustsight import config

    source = inspect.getsource(config.config_fingerprint)
    problems = []
    for token in ("campaign", "observation_seq", "cofire"):
        if token in source:
            problems.append(f"config_fingerprint references {token!r}")
    return Gate("campaign state is instrument state", not problems,
                problems or "fingerprint carries no campaign state")


def gate_campaign_expiry_is_structural() -> Gate:
    """A campaign past its TTL is never returned by the query that reads it."""
    problems: list[str] = []
    with _temp_db() as db:
        now = db.observation_seq()
        db.activate_campaign("g005:m", ["yay", "yau"], "g005",
                             ttl_obs=3, now_obs=now)
        if [c["campaign_id"] for c in db.active_campaigns(now_obs=now + 2)] != [
                "g005:m"]:
            problems.append("a live campaign was not active before its TTL")
        if db.active_campaigns(now_obs=now + 3) != []:
            problems.append("an expired campaign was still returned")
        # ...and the lapse is available to be reported once.
        if [c["campaign_id"] for c in db.expired_unannounced(now_obs=now + 3)] != [
                "g005:m"]:
            problems.append("the lapse was not reportable")
    return Gate("campaign expiry is structural", not problems,
                problems or "expired campaigns are filtered by query")


def gate_campaign_points_are_attributed() -> Gate:
    """Every campaign-influenced point names the campaign it came from (B1)."""
    problems: list[str] = []
    with _temp_db() as db:
        db.activate_campaign("g005:m", ["yyay", "yau"], "g005",
                             ttl_obs=50, now_obs=db.observation_seq())
        from trustsight.analysis.pipeline._analyze import _campaign_corroboration

        score, breakdown = _campaign_corroboration(10, [], "yyay", [])
        if score != 12:
            problems.append(f"bonus was not +min(5, 2): score={score}")
        if not breakdown or getattr(breakdown[-1], "rule_id", "") != "G007":
            problems.append("no G007 attribution entry")
        elif not breakdown[-1].evidence.get("campaign_id"):
            problems.append("the bonus entry carried no campaign_id")
    return Gate("campaign points are attributed", not problems,
                problems or "G007 names its campaign")


def gate_elevation_is_attributed() -> Gate:
    """G006 is weight 0 and names the campaign whose scope it touched."""
    problems: list[str] = []
    with _temp_db() as db:
        db.activate_campaign("g001:new.cdn", ["new.cdn"], "G001",
                             ttl_obs=50, now_obs=db.observation_seq())
        from trustsight.full_aur.pipeline import _neighborhood_elevation

        rows = _neighborhood_elevation([
            {"package": "a", "hosts_gained": ["new.cdn"]},
            {"package": "b", "hosts_gained": ["other.cdn"]},
        ])
        if len(rows) != 1 or rows[0]["rule_id"] != "G006":
            problems.append(f"expected one G006, got {rows}")
        elif (rows[0]["params"].get("campaign_id") != "g001:new.cdn"
              or rows[0]["severity"] != "INFO"):
            problems.append("G006 did not name the campaign as weight-0 INFO")
    return Gate("elevation is attributed", not problems,
                problems or "G006 names its campaign")


def gate_escalation_is_one_notch() -> Gate:
    """Licensing raises a band one step, never more, even with help."""
    from trustsight.scoring import _escalate_for_meta
    from trustsight.schema import ScoreEntry

    fired = [ScoreEntry(rule_id="M002", severity="HIGH", weight=0, reason="x"),
             ScoreEntry(rule_id="M003", severity="MEDIUM", weight=0, reason="y")]
    problems = []
    for level, expected in (("Low", "Medium"), ("Medium", "High"),
                            ("High", "Critical")):
        got = _escalate_for_meta(level, fired)
        if got != expected:
            problems.append(f"{level} -> {got}, expected {expected}")
    if _escalate_for_meta("Low", fired) != "Medium" or \
            _escalate_for_meta("Medium", fired) != "High":
        problems.append("more than one notch moved")
    return Gate("escalation is one notch", not problems,
                problems or "one notch, never more")


def gate_escalation_never_reaches_fatal() -> Gate:
    """No escalation path reaches FATAL: help amplifies, it never authorizes."""
    from trustsight.scoring import _escalate_for_meta
    from trustsight.schema import ScoreEntry

    fatal_ok = True
    for level in ("Low", "Medium", "High", "Critical"):
        reached = _escalate_for_meta(
            level, [ScoreEntry(rule_id="M002", severity="HIGH", weight=0,
                               reason="x")])
        if reached == "FATAL":
            fatal_ok = False
    # And a FATAL finding is never added to by a campaign bonus.
    with _temp_db() as db:
        db.activate_campaign("g005:m", ["fatal-pkg"], "g005",
                             ttl_obs=50, now_obs=db.observation_seq())
        from trustsight.analysis.pipeline._analyze import _campaign_corroboration

        score, _ = _campaign_corroboration(100, [], "fatal-pkg", [])
        if score != 100:
            fatal_ok = False
    return Gate("escalation never reaches fatal", fatal_ok,
                ["an escalation or bonus moved a FATAL"]
                if not fatal_ok else "never FATAL")


def gate_escalation_chains_are_rejected() -> Gate:
    """A rule that is itself licensed cannot license a third."""
    from trustsight.lint import lint_escalation_chains

    rules = [
        {"id": "R001", "escalates_when": ["R002"]},
        {"id": "R002", "escalates_when": ["R003"]},
        {"id": "R003"},
    ]
    errors = lint_escalation_chains(rules)
    ok = [f.rule_id for f in errors] == ["R002"]
    return Gate("escalation chains are rejected", ok,
                ["a chain was accepted"] if not ok else "R002 rejected")


def gate_expired_overrides_are_reported() -> Gate:
    """A lapsed override stops suppressing and its id is named (B5)."""
    import trustsight.override as ov
    from trustsight.override import RuleOverride, filter_triggered_rules

    override = RuleOverride(rule_id="H029", reason="noise", package="p",
                            created_at_obs=10, ttl_observations=5)
    saved = ov.load_overrides
    ov.load_overrides = lambda: [override]
    try:
        expired: list[str] = []
        rules = [{"rule_id": "H029", "severity": "HIGH"}]
        kept, suppressed = filter_triggered_rules(
            rules, package="p", now_obs=15, expired_out=expired)
        ok = (not suppressed and expired == ["H029"]
              and kept and kept[0].get("override_expired") is True)
    finally:
        ov.load_overrides = saved
    return Gate("expired overrides are reported", ok,
                ["a lapsed override stayed silent"] if not ok
                else "the finding returned and the expiry was named")
