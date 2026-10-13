"""The isolated git worker's clone/fetch and projection logic (A16).

These exercise ``git_worker._open_fetch`` and friends directly, in-process,
with libgit2's clone/fetch calls stubbed the way the old fetcher tests did.
The subprocess transport and isolation are covered by ``test_git_client.py``.
"""

from __future__ import annotations

import time

import pygit2
import pytest

from trustsight.sandbox import git_worker as gw


@pytest.fixture
def cache(tmp_path, monkeypatch):
    root = tmp_path / "repos"
    root.mkdir()
    return root


@pytest.fixture
def repo(cache):
    """A cached clone standing in for an AUR checkout."""
    path = cache / "demo"
    created = pygit2.init_repository(str(path))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = created.create_blob(b"pkgver=1.0\n")
    builder = created.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    created.create_commit("HEAD", author, author, "initial", builder.write(), [])
    created.remotes.create("origin", "https://aur.archlinux.org/demo.git")
    return created


def _payload(cache, upstream_mtime=None, offline=False):
    return {
        "pkg": "demo", "cache_dir": str(cache),
        "upstream_mtime": upstream_mtime, "offline": offline,
        "connect_timeout": 5, "transfer_timeout": 5,
    }


def _head_time(repo) -> int:
    return int(repo[gw._head_commit_id(repo)].commit_time)


def test_open_fetch_clones_the_aur_host(tmp_path, cache, monkeypatch):
    source = tmp_path / "source"
    src = pygit2.init_repository(str(source))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = src.create_blob(b"pkgver=1.0\n")
    builder = src.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    src.create_commit("HEAD", author, author, "initial", builder.write(), [])

    cloned: list[str] = []
    real_clone = pygit2.clone_repository

    def fake_clone(url, dest, **kwargs):
        cloned.append(url)
        return real_clone(str(source), dest, bare=kwargs.get("bare", False))

    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    result = gw._open_fetch(_payload(cache))
    assert cloned == ["https://aur.archlinux.org/demo.git"]
    assert result["fetched"] is True
    assert result["head"]


def test_a_future_dated_commit_cannot_suppress_fetches(repo, cache, monkeypatch):
    author = pygit2.Signature(
        "Tester", "tester@example.com", int(time.time()) + 10 * 365 * 86400, 0
    )
    blob = repo.create_blob(b"pkgver=2.0\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("HEAD", author, author, "future", builder.write(),
                       [repo.head.peel().id])
    assert _head_time(repo) > time.time()

    gw._record_fetch(repo)
    calls = []
    monkeypatch.setattr(pygit2.Remote, "fetch",
                        lambda self, *a, **k: calls.append(1))
    gw._open_fetch(_payload(cache, int(time.time()) + 5))
    assert calls, "future-dated commit suppressed a needed fetch"


def test_an_empty_clone_is_rebuilt(tmp_path, cache, monkeypatch):
    pygit2.init_repository(str(cache / "demo"))  # unborn HEAD, no refs
    source = tmp_path / "source"
    src = pygit2.init_repository(str(source))
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = src.create_blob(b"pkgver=1.0\n")
    builder = src.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    src.create_commit("HEAD", author, author, "initial", builder.write(), [])

    calls = []
    real_clone = pygit2.clone_repository

    def fake_clone(url, dest, **kwargs):
        calls.append(url)
        return real_clone(str(source), dest, bare=kwargs.get("bare", False))

    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    result = gw._open_fetch(_payload(cache))
    assert calls, "the empty clone was not rebuilt"
    assert result["head"]


def test_skips_the_network_when_current(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)

    def explode(*args, **kwargs):
        raise AssertionError("fetch attempted despite an up-to-date clone")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    result = gw._open_fetch(_payload(cache, fetched))
    assert result["fetched"] is False


def test_still_fetches_when_upstream_is_newer(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)
    calls = []
    monkeypatch.setattr(pygit2.Remote, "fetch",
                        lambda self, *a, **k: calls.append(1))
    gw._open_fetch(_payload(cache, fetched + 3600))
    assert calls, "expected a fetch for a clone behind upstream"


def test_a_successful_fetch_records_the_marker(repo, cache, monkeypatch):
    monkeypatch.setattr(pygit2.Remote, "fetch", lambda self, *a, **k: None)
    gw._open_fetch(_payload(cache))
    assert gw._last_fetch_time(repo) is not None


def test_a_failed_fetch_keeps_the_cached_clone(repo, cache, monkeypatch):
    path = cache / "demo"

    def explode(self, *args, **kwargs):
        raise pygit2.GitError("connection reset")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    with pytest.raises(pygit2.GitError):
        gw._open_fetch(_payload(cache))
    assert path.exists(), "a failed fetch deleted a usable clone"


def test_an_unreadable_clone_is_rebuilt(repo, cache, monkeypatch):
    path = cache / "demo"
    cloned = []

    def fake_clone(url, dest, **kwargs):
        cloned.append(url)
        return pygit2.init_repository(dest, bare=kwargs.get("bare", False))

    import shutil
    shutil.rmtree(path / ".git")
    monkeypatch.setattr(gw.pygit2, "clone_repository", fake_clone)
    gw._open_fetch(_payload(cache))
    assert cloned == ["https://aur.archlinux.org/demo.git"]


def test_offline_uses_the_cache_without_fetching(repo, cache, monkeypatch):
    fetched = gw._record_fetch(repo)

    def explode(*args, **kwargs):
        raise AssertionError("fetched while offline")

    monkeypatch.setattr(pygit2.Remote, "fetch", explode)
    result = gw._open_fetch(_payload(cache, fetched + 3600, offline=True))
    assert result["fetched"] is False


def test_offline_refuses_a_new_clone(cache):
    with pytest.raises(gw._OpError, match="TRUSTSIGHT_OFFLINE"):
        gw._open_fetch(_payload(cache, offline=True))


def test_an_unknown_member_is_refused():
    with pytest.raises(gw._OpError, match="refuses unknown member"):
        gw._file_at({"pkg": "demo", "cache_dir": "/tmp", "oid": "",
                     "name": "../../etc/passwd", "max_bytes": 10})


def test_a_path_outside_the_cache_is_refused():
    with pytest.raises(gw._OpError):
        gw._contained_repo_path("/tmp/cache", "../escape")
