"""Fetcher: the git-sandbox seam and the network-timeout configuration.

The clone/fetch *behaviour* now lives in the isolated worker and is tested in
``test_git_worker.py``; the subprocess transport is in ``test_git_client.py``;
the freshness marker is in ``sandbox/git_project.py``.  What remains here is
the parent seam: ``clone_or_fetch`` returns a bound handle, and the configured
timeouts reach the worker.
"""

import time

import pygit2
import pytest

from trustsight import fetcher
from trustsight.fetcher import clone_or_fetch
from trustsight.sandbox import git_project


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    """These tests exercise the fetch path, which TRUSTSIGHT_OFFLINE forbids."""
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)


@pytest.fixture
def repo(tmp_path):
    """A real git repository standing in for a cached AUR clone."""
    path = tmp_path / "demo"
    created = pygit2.init_repository(str(path))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = created.create_blob(b"pkgver=1.0\n")
    builder = created.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    created.create_commit(
        "HEAD", author, author, "initial", builder.write(), []
    )
    created.remotes.create("origin", "https://aur.archlinux.org/demo.git")
    return created


# --- the freshness marker (now owned by git_project) -------------------------


def test_is_current_when_fetched_at_or_after_upstream(repo):
    fetched = git_project.record_fetch(repo)
    assert git_project._is_current(repo, fetched) is True
    assert git_project._is_current(repo, fetched - 60) is True


def test_is_not_current_when_upstream_is_newer_than_our_fetch(repo):
    fetched = git_project.record_fetch(repo)
    assert git_project._is_current(repo, fetched + 60) is False


def test_is_not_current_without_a_marker(repo):
    """A clone with no marker falls back to HEAD's commit time."""
    assert git_project.last_fetch_time(repo) is None
    assert git_project._is_current(repo, int(time.time()) + 3600) is False
    assert git_project._is_current(repo, int(time.time()) - 3600) is True


# --- the git-sandbox seam ---------------------------------------------------


class _FakeSession:
    instances: list["_FakeSession"] = []

    def __init__(self):
        self.calls: list[dict] = []
        self.closed = False
        _FakeSession.instances.append(self)

    def open_fetch(self, pkg, cache_dir, upstream_mtime, offline,
                   connect, transfer):
        self.calls.append({
            "pkg": pkg, "cache_dir": cache_dir,
            "upstream_mtime": upstream_mtime, "offline": offline,
            "connect": connect, "transfer": transfer,
        })
        return {"path": str(cache_dir), "head": "", "fetched": True,
                "marker_time": None, "received_bytes": 0}

    def close(self):
        self.closed = True


def test_clone_or_fetch_delegates_to_the_isolated_worker(tmp_path, monkeypatch):
    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)
    _FakeSession.instances = []
    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _FakeSession)

    project = clone_or_fetch("demo", 1234)

    session = _FakeSession.instances[-1]
    assert session.calls == [{
        "pkg": "demo", "cache_dir": str(cache),
        "upstream_mtime": 1234, "offline": False,
        "connect": fetcher.DEFAULT_CONNECT_TIMEOUT,
        "transfer": fetcher.DEFAULT_TRANSFER_TIMEOUT,
    }]
    project.close()
    assert session.closed, "the worker session was not closed"


def test_clone_or_fetch_reports_a_dead_worker_as_a_fetch_failure(tmp_path, monkeypatch):
    from trustsight.sandbox.git_client import GitSandboxUnavailable

    cache = tmp_path / "repos"
    cache.mkdir()
    monkeypatch.setattr("trustsight.fetcher.CACHE_DIR", cache)

    class _Dead:
        def __init__(self):
            pass

        def open_fetch(self, *a, **k):
            raise GitSandboxUnavailable("worker died")

        def close(self):
            pass

    monkeypatch.setattr("trustsight.sandbox.git_client.GitSession", _Dead)
    with pytest.raises(fetcher._TimeoutError, match="git sandbox unavailable"):
        clone_or_fetch("demo")


# --- network timeout configuration ------------------------------------------


def test_network_timeouts_reach_the_worker(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 4, "network_transfer_timeout": 9}},
    )
    assert fetcher._network_timeout_values() == (4, 9)


def test_network_timeouts_fall_back_when_unconfigured(monkeypatch):
    monkeypatch.setattr(
        "trustsight.config.load_config",
        lambda: {"limits": {"network_connect_timeout": 0}},
    )
    assert fetcher._network_timeout_values() == (
        fetcher.DEFAULT_CONNECT_TIMEOUT, fetcher.DEFAULT_TRANSFER_TIMEOUT,
    )
