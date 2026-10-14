import json
import shutil
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from trustsight import review as engine
from trustsight.cli import app
from trustsight.safe_text import clean

pytestmark = pytest.mark.skipif(
    not shutil.which("pacman"),
    reason="pacman not available (non-Arch system)",
)


def help_text(*args) -> str:
    """The help output for *args*, with the styling removed.

    Rich styles an option's leading hyphen as its own span, so the bytes
    of ``--repo`` are ``-\x1b[0m\x1b[1;36m-repo``: the literal substring
    is not in the output and a plain ``in`` check fails even though the
    flag is right there.  Which spans Rich chooses to split is a
    presentation detail that moves between versions, so asserting on the
    decorated bytes makes the test fail for reasons that have nothing to
    do with the CLI.  ``safe_text.clean`` is the project's own escape
    stripper; using it here means these tests exercise it too.
    """
    result = CliRunner().invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return clean(result.output)


def test_cli_help():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0


def test_cli_no_args_runs_help():
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 2  # typer shows help and exits with code 2


def test_cli_review_help():
    result = CliRunner().invoke(app, ["review", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_help():
    result = CliRunner().invoke(app, ["inspect", "--help"])
    assert result.exit_code == 0


def test_cli_history_help():
    result = CliRunner().invoke(app, ["history", "--help"])
    assert result.exit_code == 0


def test_cli_inspect_no_args():
    result = CliRunner().invoke(app, ["inspect"])
    assert result.exit_code != 0


def test_cli_history_no_args():
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code != 0


def test_cli_review_runs(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages", return_value=([], 0)):
        result = CliRunner().invoke(app, ["review", "--limit", "5"])
        assert result.exit_code == 0


# --- Discovery flags ---

def test_cli_review_help_shows_flags():
    out = help_text("review", "--help")
    for flag in ("--repo", "--foreign", "--all-repos"):
        assert flag in out


@pytest.fixture
def review_env(tmp_path, monkeypatch):
    """Shared setup for discovery-flag tests: isolate config + mock discovery."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    return tmp_path


def test_cli_review_flag_repo(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs == {
            "repos": ["aur"],
            "include_foreign": False,
            "all_repos_flag": False,
            "all_packages": False,
            "json_output": False,
            "_warn": mock_disc.call_args[1]["_warn"],
            "force_refresh": False,
        }


def test_cli_review_flag_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--foreign"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos_flag"] is False


def test_cli_review_flag_all_repos(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--all-repos"])
        assert result.exit_code == 0, result.stdout
        mock_disc.assert_called_once()
        _, kwargs = mock_disc.call_args
        assert kwargs["all_repos_flag"] is True
        assert kwargs["repos"] == []
        assert kwargs["include_foreign"] is False


def test_cli_review_flag_repo_twice(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--repo", "testing"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur", "testing"]


def test_cli_review_flag_repo_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "aur", "--foreign"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_flag_all_repos_plus_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--all-repos", "--foreign"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["all_repos_flag"] is True
        assert kwargs["include_foreign"] is True


# --- Config-driven discovery (no CLI flags) ---

def _make_config_with_discovery(tmp_path, monkeypatch, **discovery_overrides):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    cfg_dir = tmp_path / ".config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.toml"

    from trustsight.config import DEFAULT_CONFIG
    if cfg_path.exists():
        cfg_path.unlink()
    text = DEFAULT_CONFIG
    import re
    text = re.sub(r"\n\[discovery\].*?(?=\n\[|\Z)", "", text, flags=re.DOTALL)
    text = text.rstrip() + "\n"
    discovery_lines = [
        "[discovery]",
        f'default_repos = {discovery_overrides.get("default_repos", "[]")}',
        f'include_foreign = {str(discovery_overrides.get("include_foreign", False)).lower()}',
        f'all_repos = {str(discovery_overrides.get("all_repos", False)).lower()}',
    ]
    text += "\n".join(discovery_lines) + "\n"
    cfg_path.write_text(text)


def test_cli_review_config_default_repos(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["aur"]
        assert kwargs["include_foreign"] is True


def test_cli_review_config_cli_overrides(tmp_path, monkeypatch):
    _make_config_with_discovery(
        tmp_path, monkeypatch,
        default_repos='["aur"]',
        include_foreign=True,
    )

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review", "--repo", "cli-repo"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["repos"] == ["cli-repo"]
        assert kwargs["include_foreign"] is False


def test_cli_review_config_no_flags_fallback_foreign(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages") as mock_disc:
        mock_disc.return_value = ([], 0)
        result = CliRunner().invoke(app, ["review"])
        assert result.exit_code == 0, result.stdout
        _, kwargs = mock_disc.call_args
        assert kwargs["include_foreign"] is True
        assert kwargs["repos"] == []
        assert kwargs["all_repos_flag"] is False


def test_cli_history_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    result = CliRunner().invoke(app, ["history", "nonexistentpkg"])
    assert result.exit_code == 2
    assert "has not been analysed yet" in result.output


def test_cli_inspect_calls_analyze(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db
    init_db()
    # The installed gate is the local pacman set.
    monkeypatch.setattr(
        "trustsight.discovery.get_all_installed", lambda: {"testpkg": "1.0"}
    )

    with (
        patch("trustsight.cli.inspect.commands.analyze_package") as mock_analyze,
        patch("trustsight.discovery.get_aur_package_info") as mock_aur,
    ):
        from trustsight.schema import PackageFact, DiffSummary
        mock_aur.return_value = {"testpkg": {"Version": "1.1"}}
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        result = CliRunner().invoke(app, ["inspect", "testpkg"])
        assert result.exit_code == 0, result.stdout
        mock_analyze.assert_called_once_with("testpkg", depth=None, record=False, full_recipe=False)


def test_cli_inspect_json_emits_the_body(tmp_path, monkeypatch):
    """`inspect --json` must print the body, not silently drop it.

    The single-result path returned ``report_body`` to a caller that threw
    the value away, so the command exited 0 with empty stdout. The
    ``--last`` path printed its JSON, so only the single-package surface was
    affected, and the output-parity test missed it by building the expected
    body directly rather than through the CLI.
    """
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)

    from trustsight.config import ensure_default_configs
    ensure_default_configs()
    from trustsight.db import init_db
    init_db()
    monkeypatch.setattr(
        "trustsight.discovery.get_all_installed", lambda: {"testpkg": "1.0"}
    )

    with (
        patch("trustsight.cli.inspect.commands.analyze_package") as mock_analyze,
        patch("trustsight.discovery.get_aur_package_info") as mock_aur,
    ):
        from trustsight.schema import PackageFact, DiffSummary
        mock_aur.return_value = {"testpkg": {"Version": "1.1"}}
        mock_analyze.return_value = PackageFact(
            package_name="testpkg",
            new_version="1.1",
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        )
        result = CliRunner().invoke(app, ["inspect", "testpkg", "--json", "--score"])
        assert result.exit_code == 0, result.stdout
        body = json.loads(result.stdout)
        assert body["package"] == "testpkg"
        assert "findings" in body


# --- batch orchestration ---

def _fact(name, score=0):
    from trustsight.schema import DiffSummary, PackageFact
    return PackageFact(
        package_name=name,
        new_version="1.1",
        diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        final_score=score,
    )


def test_batch_prefetches_then_analyses_without_refetching(monkeypatch):
    """Every package is fetched once, up front, and not again per analysis.

    The fetch is the slow step, so the batch warms all the clones
    concurrently and hands each analysis the commit time it just saw;
    analyze_package then finds the clone current and skips the network.
    """
    fetched = []

    class FakeRepo:
        def last_fetch_time(self):
            return 1700000000

        def close(self):
            pass

    monkeypatch.setattr(
        "trustsight.fetcher.clone_or_fetch",
        lambda name, mtime=None: fetched.append((name, mtime)) or FakeRepo(),
    )

    seen = {}

    def fake_analyze(name, **kwargs):
        seen[name] = kwargs
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    pkgs = [
        {"name": "alpha", "current_version": "1.0", "latest_version": "1.1",
         "last_modified": 1699999999},
        {"name": "beta", "current_version": "2.0", "latest_version": "2.1"},
    ]
    results = engine.analyze_outdated_batch(pkgs)

    assert [r["package"] for r in results] == ["alpha", "beta"]
    assert sorted(name for name, _ in fetched) == ["alpha", "beta"]
    # the RPC's LastModified is passed through to the fetcher
    assert dict(fetched)["alpha"] == 1699999999
    # and each analysis receives the freshness hint plus the known version,
    # so it neither refetches nor forks pacman.  The hint is the AUR's own
    # timestamp, never a value derived from the upstream commit.
    assert seen["alpha"]["upstream_mtime"] == 1699999999
    assert seen["alpha"]["installed_version"] == "1.0"
    # beta had no LastModified, so it falls back to our own fetch time
    assert seen["beta"]["upstream_mtime"] == 1700000000


def test_prefetch_deadline_abandons_a_stalled_fetch(monkeypatch):
    """The deadline must return, not wait for the stalled fetch to finish.

    Shutting the pool down with wait=True made the deadline cosmetic: the
    warning printed, then the run blocked - with a frozen progress bar - for
    as long as the hung fetch took.  What the deadline drops is re-fetched
    during analysis.
    """
    import threading
    import time

    release = threading.Event()
    started = threading.Event()

    class _Project:
        def last_fetch_time(self):
            return None

        def close(self):
            pass

    def fake_fetch(name, mtime=None):
        if name == "stalled":
            started.set()
            release.wait(30)
        return _Project()

    monkeypatch.setattr("trustsight.fetcher.clone_or_fetch", fake_fetch)
    monkeypatch.setattr(
        engine, "load_config", lambda: {"limits": {"prefetch_timeout": 1}}
    )

    pkgs = [
        {"name": "stalled", "last_modified": 111},
        {"name": "quick", "last_modified": 222},
    ]
    phases = []
    began = time.monotonic()
    try:
        hints = engine.prefetch(
            pkgs, lambda cur, total, phase: phases.append((cur, phase))
        )
        elapsed = time.monotonic() - began
    finally:
        release.set()

    assert started.is_set(), "the stalled fetch never started"
    assert elapsed < 10, f"prefetch waited {elapsed:.1f}s on an abandoned fetch"
    assert hints == {"quick": 222}
    # the bar is repainted on the way out, so it never freezes mid-fetch
    assert phases[-1][0] == -1


def test_one_bad_package_does_not_end_the_run(monkeypatch):
    """A failure is contained: other packages are still analysed."""
    monkeypatch.setattr(engine, "prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    def fake_analyze(name, **kwargs):
        if name == "broken":
            raise RuntimeError("boom")
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)

    results = engine.analyze_outdated_batch([
        {"name": "broken", "current_version": "1.0"},
        {"name": "fine", "current_version": "1.0"},
    ])
    scored = [r for r in results if not r.get("failed")]
    assert [r["package"] for r in scored] == ["fine"]
    # the failure is surfaced, not swallowed
    assert [r["package"] for r in results if r.get("failed")] == ["broken"]


def test_a_failed_package_is_reported_not_dropped(monkeypatch):
    """A package that cannot be analysed must still appear in the review.

    Dropping it made an unvetted package indistinguishable from a clean
    one, so anything able to provoke a crash could keep itself out of the
    report entirely.
    """
    monkeypatch.setattr(engine, "prefetch", lambda pkgs, cb=None: {})
    monkeypatch.setattr(engine, "verdict_for", lambda fact: "ok")

    def fake_analyze(name, **kwargs):
        if name == "evil":
            raise RuntimeError("crafted crash")
        return _fact(name)

    monkeypatch.setattr(engine, "analyze_package", fake_analyze)

    results = engine.analyze_outdated_batch([
        {"name": "evil", "current_version": "1.0", "latest_version": "1.1"},
        {"name": "good", "current_version": "1.0", "latest_version": "1.1"},
    ])

    by_name = {r["package"]: r for r in results}
    assert set(by_name) == {"evil", "good"}
    evil = by_name["evil"]
    assert evil["failed"] is True
    assert evil["score"] is None, "a failed analysis must not carry a clean score"
    assert evil["risk"] == "Error"
    assert "NOT vetted" in evil["verdict"]


def test_failed_packages_render_without_crashing(monkeypatch, tmp_path):
    """The table must cope with the absent score of a failed package."""
    from trustsight import cli

    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(
        cli.review, "_analyze_outdated_batch",
        lambda pkgs, cb=None, verbose=False, depth=None, record=False: [
            {"package": "ok", "score": 5, "risk": "Low", "verdict": "fine",
             "first_seen": False},
            {"package": "bad", "score": None, "risk": "Error", "failed": True,
             "verdict": "Analysis failed (RuntimeError): this package was NOT vetted.",
             "first_seen": False},
        ],
    )
    # exercises the rich renderer, which formats the score cell
    cli.review._run_analysis_loop([{"name": "ok"}, {"name": "bad"}], 10, False, False, False)


# --- Regression tests for metadata-dispatch bugs ---


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_first_run_reviews_in_same_call(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """A first run fetches the snapshot and reviews against it.

    It used to return ``(None, 0)`` and tell the user to run again; the
    first invocation now continues with the snapshot it just saved.
    """
    from trustsight.cli.review import _discover_packages

    mock_load.return_value = None
    mock_fetch.return_value = {"some-pkg": {"Version": "2.0"}}
    mock_config.return_value = {"discovery": {"show_unmatched": True}}
    mock_installed.return_value = [
        {"name": "some-pkg", "current_version": "1.0"}
    ]

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=False, _warn=lambda msg: None,
    )
    assert result is not None
    assert [p["name"] for p in result] == ["some-pkg"]
    assert total == 1
    mock_fetch.assert_called_once()
    mock_save.assert_called_once()


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_all_includes_snapshot_misses(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """--all includes packages not in the AUR snapshot by default."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = ({"known-pkg": {"Version": "2.0"}}, int(time.time()))
    mock_config.return_value = {"discovery": {"show_unmatched": True}}
    mock_installed.return_value = [
        {"name": "known-pkg", "current_version": "1.0"},
        {"name": "unknown-pkg", "current_version": "1.0"},
    ]

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=True, _warn=lambda msg: None,
    )

    names = [p["name"] for p in result]
    assert "known-pkg" in names
    assert "unknown-pkg" in names
    assert total == 2


@patch("trustsight.review.get_installed_packages")
@patch("trustsight.review.load_config")
@patch("trustsight.full_aur.metadata.load_snapshot")
@patch("trustsight.full_aur.metadata.fetch_metadata")
@patch("trustsight.full_aur.metadata.save_metadata")
def test_discover_packages_all_skips_snapshot_misses_when_configured(
    mock_save, mock_fetch, mock_load, mock_config, mock_installed
):
    """With show_unmatched=false, --all skips packages not in the AUR snapshot."""
    import time

    from trustsight.cli.review import _discover_packages

    mock_load.return_value = ({"known-pkg": {"Version": "2.0"}}, int(time.time()))
    mock_config.return_value = {"discovery": {"show_unmatched": False}}
    mock_installed.return_value = [
        {"name": "known-pkg", "current_version": "1.0"},
        {"name": "unknown-pkg", "current_version": "1.0"},
    ]

    result, total = _discover_packages(
        repos=[], include_foreign=True, all_repos_flag=False,
        all_packages=True, _warn=lambda msg: None,
    )

    names = [p["name"] for p in result]
    assert "known-pkg" in names
    assert "unknown-pkg" not in names
    assert total == 2


# --- The limit, and what it leaves unread ---


def test_the_summary_names_the_packages_the_limit_skipped():
    """A review that stops early has a coverage gap, and says so.

    `--limit 5` against 40 outdated packages printed "5 package(s) needing
    update and reviewed": the count of packages *needing* an update was
    silently replaced by the count the limit allowed through, so the number
    was wrong in the direction that reads as reassuring, and the 35 skipped
    were never mentioned at all.
    """
    from trustsight.cli.review import _summary_caption

    caption = _summary_caption(
        reviewed=5, failed=0, flagged=0, total_installed=120,
        all_packages=False, outdated_total=40, show_score=False,
    )
    assert "35 more needed review and were NOT read" in caption
    assert "--limit 0" in caption

    whole = _summary_caption(
        reviewed=40, failed=0, flagged=0, total_installed=120,
        all_packages=False, outdated_total=40, show_score=False,
    )
    assert "NOT read" not in whole, "nothing was skipped, so say nothing"


def test_the_configured_review_limit_is_read(tmp_path, monkeypatch):
    """`[limits] default_review_limit` shipped set to 20 and did nothing.

    The flag's own default of 0 won on every invocation, so a user who set
    the documented key saw no change. It is honoured now, and the shipped
    value is 0 - a review that reads everything - because the alternative
    silently narrows what an existing install covers.
    """
    import tomllib

    from trustsight.config import DEFAULT_CONFIG

    assert tomllib.loads(DEFAULT_CONFIG)["limits"]["default_review_limit"] == 0

    seen = {}

    def _fake_loop(pkgs, limit, *a, **k):
        seen["limit"] = limit

    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    from trustsight.config import ensure_default_configs
    ensure_default_configs()

    with patch("trustsight.cli.review._discover_packages",
               return_value=([{"name": "p", "current_version": "1"}], 1)), \
         patch("trustsight.cli.review._run_analysis_loop", _fake_loop), \
         patch("trustsight.cli.review.load_config",
               return_value={"limits": {"default_review_limit": 7}}):
        result = CliRunner().invoke(app, ["review"])
    assert result.exit_code == 0, result.output
    assert seen["limit"] == 7, "the configured default was ignored"

    # An explicit `--limit 0` means all of them and must beat the config.
    with patch("trustsight.cli.review._discover_packages",
               return_value=([{"name": "p", "current_version": "1"}], 1)), \
         patch("trustsight.cli.review._run_analysis_loop", _fake_loop), \
         patch("trustsight.cli.review.load_config",
               return_value={"limits": {"default_review_limit": 7}}):
        CliRunner().invoke(app, ["review", "--limit", "0"])
    assert seen["limit"] == 0


# --- Snapshot staleness ---
#
# The snapshot was downloaded on first run and then reused forever, so a
# machine whose AUR packages had moved on was told "No outdated packages
# found" - the tool's one job, answered wrongly and quietly.  Reported from a
# user's machine running 0.13.1 with four pending AUR updates.

_HOUR = 3600
