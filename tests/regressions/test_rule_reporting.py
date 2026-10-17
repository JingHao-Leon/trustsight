"""What a recipe does not say, and a shipped fix that never reached an install."""

import pytest

# ---------------------------------------------------------------------------
# Audit M2 - a recipe that pins says so; one that does not said nothing
#
# P005 reports a commit pin and P006 a tag pin, so a recipe tracking a branch
# produced no line at all and read the same as one that pins.  Reported at
# weight 0 rather than as a coverage gap: it is true of every VCS package by
# design, and a gap fires 20% of the benign corpus into Inconclusive.
#
# A `#commit=` or `#tag=` fragment is a declared pin (P005/P006); only a
# branch, or no fragment at all, is the absence P008 states.  Counting a tag
# here called a tag-pinned source unpinned, contradicting P006.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry,expected", [
    ("git+https://ex.invalid/d.git#branch=main", True),
    ("git+https://ex.invalid/d.git", True),
    ("git+https://ex.invalid/d.git#tag=v1.2", False),
    ("git+https://ex.invalid/d.git#tag=$_tag", False),
    ("git+https://ex.invalid/d.git#commit=" + "b" * 40, False),
    ("git+https://ex.invalid/d.git#commit=$_commit", False),
    ("https://ex.invalid/d-1.0.tar.gz", False),
])
def test_p008_reports_only_a_missing_pin(entry, expected):
    from trustsight.coverage import unpinned_source_refs

    assert bool(unpinned_source_refs(f"+source=({entry})\n")) is expected


def test_p008_carries_no_weight():
    """A declared fact may not move the band; that was the whole decision."""
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,6 @@\n"
        '+source=("git+https://ex.invalid/d.git#branch=main")\n'
    )
    entries = [e for e in scan_diff(diff, package_name="p").score_breakdown
               if e.rule_id == "P008"]
    assert entries, "P008 must be reachable"
    assert all(e.weight == 0 for e in entries)


# ---------------------------------------------------------------------------
# A URL a recipe only prints is not a source
#
# X006 (HIGH), the unknown bucket tier, H003 and C011 all read URLs from any
# added line.  A `.install` that echoes a local admin console URL flipped a
# package to Critical, and X006 is exactly the signal reviewers are told not
# to dismiss.  A loopback/private host distributes nothing, so it is excluded
# from the family; a public raw IP still fires.
# ---------------------------------------------------------------------------


def test_a_printed_localhost_url_is_not_a_source():
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,5 @@\n"
        " package() {\n"
        '   install -Dm644 x "$pkgdir/x"\n'
        '+  echo "The web console is at http://127.0.0.1:8787/admin"\n'
        " }\n"
    )
    ids = {e.rule_id for e in scan_diff(diff, package_name="demo").score_breakdown}
    assert not (ids & {"X006", "R046", "R047", "H003", "C011"})


def test_a_public_raw_ip_source_still_fires():
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n"
        '+source=("http://8.8.8.8:8787/pkg.tar.gz")\n'
    )
    ids = {e.rule_id for e in scan_diff(diff, package_name="demo").score_breakdown}
    assert {"X006", "R046", "R047"} <= ids


def test_a_printed_public_url_is_not_a_source():
    """The URL rules read declarations and fetches, not a printed string."""
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,5 @@\n"
        " package() {\n"
        '   install -Dm644 x "$pkgdir/x"\n'
        '+  echo "status at http://8.8.8.8:8787/status"\n'
        " }\n"
    )
    ids = {e.rule_id for e in scan_diff(diff, package_name="demo").score_breakdown}
    assert not (ids & {"X006", "R046", "R047", "H003", "C011"})


def test_a_fetched_url_still_fires():
    """The same URL passed to a fetch client is a source."""
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,5 @@\n"
        " package() {\n"
        '   install -Dm644 x "$pkgdir/x"\n'
        "+  curl -O http://8.8.8.8:8787/pkg.tar.gz\n"
        " }\n"
    )
    ids = {e.rule_id for e in scan_diff(diff, package_name="demo").score_breakdown}
    assert {"X006", "R046", "R047"} <= ids


# ---------------------------------------------------------------------------
# A shipped *pattern* fix never reached an existing install, and nothing said so
#
# `drifted_shipped_rules` parsed `pattern` into its field dict and then
# compared everything except it, so rules.toml - written once at install
# time - kept its original patterns forever with no report.  Both the escape
# guard and the executor list above landed that way.
# ---------------------------------------------------------------------------


def test_pattern_drift_is_reported(tmp_path, monkeypatch):
    import trustsight.config as cfg

    monkeypatch.setattr(cfg, "CONFIG_DIR", tmp_path)
    shipped = next(r for r in cfg.shipped_rules() if r["id"] == "R001")
    (tmp_path / "rules.toml").write_text(
        '[[rules]]\nid = "R001"\nname = "Curl Pipe to Shell"\n'
        "pattern = 'curl.*\\\\|\\\\s*(?:bash|sh)'\n"
        'severity = "CRITICAL"\ncategory = "network_execution"\n'
        'match_target = "resolved"\n'
    )
    cfg._rules_cache = None
    drift = {(rid, field) for rid, field, _on_disk, _shipped in
             cfg.drifted_shipped_rules()}
    cfg._rules_cache = None
    assert ("R001", "pattern") in drift
    assert "pdk" in shipped["pattern"], "the shipped pattern is the wide one"
