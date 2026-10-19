"""The G-series cross-package correlation."""

from trustsight.analysis.correlation import (
    coordinated_adoption,
    correlate,
    shared_added_literal,
    shared_gained_host,
    watchlisted_maintainer,
)


def _records():
    return [
        {"package": "a", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "b", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": ["B" * 300]},
        {"package": "c", "hosts_gained": ["new.cdn"], "maintainer": "m@x",
         "adoption": True, "added_literals": []},
        {"package": "d", "hosts_gained": [], "maintainer": "other@y",
         "adoption": False, "added_literals": []},
    ]


def test_shared_gained_host_fires_at_threshold():
    found = shared_gained_host(_records(), min_packages=3)
    assert [f["rule_id"] for f in found] == ["G001"]
    assert found[0]["params"]["members"] == ["a", "b", "c"]
    assert shared_gained_host(_records(), min_packages=4) == []


def test_shared_added_literal_fires_and_redacts_content():
    found = shared_added_literal(_records(), min_packages=2, min_length=64)
    assert [f["rule_id"] for f in found] == ["G002"]
    assert "B" * 300 not in found[0]["match"]
    assert found[0]["params"]["literal_length"] == 300


def test_coordinated_adoption_fires_at_threshold():
    found = coordinated_adoption(_records(), min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert coordinated_adoption(_records(), min_members=4) == []


def test_coordinated_adoption_cites_the_temporal_predicates():
    records = [
        {"package": "a", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
        {"package": "b", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H086"]},
        {"package": "c", "maintainer": "m@x", "adoption": True,
         "adoption_predicates": ["H044"]},
    ]
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["params"]["predicates"] == ["H044", "H086"]


def test_coordinated_adoption_requires_unrelated_members():
    """A maintainer adopting one variant family (all from one repo) is H052's
    shape, not a coordinated adoption."""
    related = [
        {"package": "a", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "b", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
        {"package": "c", "maintainer": "m", "adoption": True,
         "adoption_predicates": ["H044"], "source_repos": ["https://x/one"]},
    ]
    assert coordinated_adoption(related, min_members=3) == []

    unrelated = [dict(r, source_repos=[f"https://x/{r['package']}"])
                 for r in related]
    found = coordinated_adoption(unrelated, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]
    assert found[0]["params"]["repos"] == [
        "https://x/a", "https://x/b", "https://x/c"]


def test_coordinated_adoption_keeps_firing_without_repo_data():
    """An unproven relationship is not evidence of one: missing repo data
    preserves the group rather than quietly dropping it."""
    records = [
        {"package": "a", "maintainer": "m", "adoption": True},
        {"package": "b", "maintainer": "m", "adoption": True},
        {"package": "c", "maintainer": "m", "adoption": True},
    ]
    assert [f["rule_id"] for f in coordinated_adoption(records, 3)] == ["G003"]


def test_coordinated_adoption_stands_down_for_a_variant_family_by_name():
    """New packages land in the window with no repo data yet, which made
    the repo relatedness test vacuous for exactly the case it exists for:
    a maintainer releasing appattic, appattic-bin and appattic-qt in one
    cycle is one project by name, not a coordinated adoption."""
    records = [
        {"package": "appattic", "maintainer": "m", "adoption": True},
        {"package": "appattic-bin", "maintainer": "m", "adoption": True},
        {"package": "appattic-qt", "maintainer": "m", "adoption": True},
    ]
    assert coordinated_adoption(records, min_members=3) == []


def test_coordinated_adoption_fires_when_one_member_is_unrelated():
    """Two variants plus one genuinely unrelated adoption stays a group:
    the unrelated member is the signal, not noise."""
    records = [
        {"package": "appattic", "maintainer": "m", "adoption": True},
        {"package": "appattic-bin", "maintainer": "m", "adoption": True},
        {"package": "unrelated-tool", "maintainer": "m", "adoption": True},
    ]
    found = coordinated_adoption(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G003"]


def test_g003_escalates_for_a_first_seen_account_adopting_dormant_packages(
        monkeypatch):
    import time

    now = time.time()
    dormant = int(now - 180 * 86400 - 86400)
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper", "adoption": True,
         "adoption_predicates": ["H086"], "last_modified": dormant}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00" if m == "fennekuiper" else None,
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["novel"] is True
    assert found[0]["params"]["dormant_count"] == 3


def test_g003_stays_medium_for_an_established_maintainer(monkeypatch):
    import time

    now = time.time()
    dormant = int(now - 180 * 86400 - 86400)
    records = [
        {"package": f"pkg{i}", "maintainer": "established", "adoption": True,
         "adoption_predicates": ["H044"], "last_modified": dormant}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2020-01-01 00:00:00",
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["params"]["novel"] is False


def test_g003_stays_medium_when_targets_are_active(monkeypatch):
    import time

    now = time.time()
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper", "adoption": True,
         "adoption_predicates": ["H086"], "last_modified": int(now - 30 * 86400)}
        for i in range(3)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    found = coordinated_adoption(records, min_members=3)
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["params"]["dormant_count"] == 0


def test_g009_reports_a_watchlisted_maintainer(monkeypatch):
    records = [{"package": "xsp", "maintainer": "fennekuiper"}]
    monkeypatch.setattr(
        "trustsight.watchlist.load_watchlist",
        lambda path=None: {"h1": "June 2026 orphan sweep"},
    )
    monkeypatch.setattr("trustsight.watchlist.local_hash", lambda n: "h1")
    found = watchlisted_maintainer(records, None)
    assert [f["rule_id"] for f in found] == ["G009"]
    assert found[0]["severity"] == "INFO"
    assert found[0]["params"]["members"] == ["xsp"]


def test_g009_is_silent_without_a_watchlist(monkeypatch):
    monkeypatch.setattr("trustsight.watchlist.load_watchlist",
                        lambda path=None: {})
    assert watchlisted_maintainer(
        [{"package": "x", "maintainer": "m"}], None) == []


def test_correlate_honors_configured_thresholds():
    config = {"thresholds": {
        "g_host": {"min_packages": 3},
        "g_blob": {"min_packages": 2, "min_length": 64},
        "g_adopt": {"min_members": 3},
    }}
    ids = {f["rule_id"] for f in correlate(_records(), config)}
    assert ids == {"G001", "G002", "G003"}


def test_correlate_is_empty_without_clusters():
    assert correlate([{"package": "only"}], None) == []


def test_impersonation_campaign_groups_clones_by_maintainer():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": "yyay", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "parru", "maintainer": "marchos1as",
         "impersonated_target": "paru"},
        {"package": "yau", "maintainer": "marchos1as",
         "impersonated_target": "yay"},
        {"package": "koboldcpp-cuda", "maintainer": "TheBill2001",
         "impersonated_target": ""},
    ]
    found = impersonation_campaign(records, min_members=3)
    assert [f["rule_id"] for f in found] == ["G005"]
    assert found[0]["severity"] == "HIGH"
    assert found[0]["params"]["members"] == ["parru", "yau", "yyay"]
    assert found[0]["params"]["targets"] == ["paru", "yay"]


def test_a_lone_clone_is_not_a_campaign():
    from trustsight.analysis.correlation import impersonation_campaign

    records = [{"package": "yyay", "maintainer": "m",
                "impersonated_target": "yay"}]
    assert impersonation_campaign(records, min_members=2) == []


def test_ownerless_clones_are_not_grouped_into_a_campaign():
    """An empty maintainer is not evidence that unrelated ownerless clones
    share an operator; they stay individual H029 findings."""
    from trustsight.analysis.correlation import impersonation_campaign

    records = [
        {"package": name, "maintainer": "", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    assert impersonation_campaign(records, min_members=3) == []


def test_correlate_includes_the_impersonation_campaign():
    records = [
        {"package": name, "maintainer": "m", "impersonated_target": "yay"}
        for name in ("yyay", "yau", "yayy")
    ]
    ids = {f["rule_id"] for f in correlate(records, None)}
    assert "G005" in ids


def test_g008_fires_for_first_seen_account_adopting_dormant_packages(
        monkeypatch):
    import time
    from trustsight.analysis.correlation import first_seen_adoption_burst

    now = time.time()
    dormant_cutoff = now - 180 * 86400

    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": int(dormant_cutoff - 86400)}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00" if m == "fennekuiper" else None,
    )
    found = first_seen_adoption_burst(records, None)
    assert [f["rule_id"] for f in found] == ["G008"]
    assert found[0]["params"]["maintainer"] == "fennekuiper"
    assert found[0]["params"]["dormant_count"] == 5


def test_g008_requires_first_seen_account(monkeypatch):
    from trustsight.analysis.correlation import first_seen_adoption_burst

    records = [
        {"package": f"pkg{i}", "maintainer": "established",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": 1000}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2020-01-01 00:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_requires_dormant_targets(monkeypatch):
    import time
    from trustsight.analysis.correlation import first_seen_adoption_burst

    now = time.time()
    records = [
        {"package": f"pkg{i}", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": int(now - 30 * 86400)}
        for i in range(5)
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []


def test_g008_requires_min_packages(monkeypatch):
    from trustsight.analysis.correlation import first_seen_adoption_burst

    records = [
        {"package": "pkg0", "maintainer": "fennekuiper",
         "adoption": True, "adoption_predicates": ["H086"],
         "adoption_observed_at": "2026-10-18 12:00:00",
         "last_modified": 1000},
    ]
    monkeypatch.setattr(
        "trustsight.db.maintainer_first_seen",
        lambda m: "2026-10-18 12:00:00",
    )
    assert first_seen_adoption_burst(records, None) == []
