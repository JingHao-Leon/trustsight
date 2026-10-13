"""The isolated git worker's clone/fetch and projection logic (A16).

These exercise ``git_worker._open_fetch`` and friends directly, in-process,
with libgit2's clone/fetch calls stubbed the way the old fetcher tests did.
The subprocess transport and isolation are covered by ``test_git_client.py``.
"""

from __future__ import annotations

import base64
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


def test_diff_projects_a_metadata_change(tmp_path, cache):
    repo = pygit2.init_repository(str(cache / "diffdemo"))
    author = pygit2.Signature("Tester", "tester@example.com")

    def commit(text, parents):
        blob = repo.create_blob(text)
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        return str(repo.create_commit("HEAD", author, author, "c",
                                      builder.write(), parents))

    old = commit(b"pkgver=1.0\n", [])
    new = commit(b"pkgver=2.0\n", [pygit2.Oid(hex=old)])
    out = gw._diff({"pkg": "diffdemo", "cache_dir": str(cache),
                    "old": old, "new": new, "context_lines": 3,
                    "max_bytes": None})
    assert "pkgver=2.0" in out["unified"]
    assert out["summary"]["files_changed"] == ["PKGBUILD"]
    assert out["truncated"] is False


def test_diff_refuses_an_invalid_commit_id(cache):
    with pytest.raises(gw._OpError, match="invalid commit id"):
        gw._diff({"pkg": "d", "cache_dir": str(cache), "old": "not-an-oid",
                  "new": "", "context_lines": 3, "max_bytes": None})


def _commit_files(repo, files, parents):
    builder = repo.TreeBuilder()
    for name, data in files.items():
        builder.insert(name, repo.create_blob(data), pygit2.GIT_FILEMODE_BLOB)
    author = pygit2.Signature("Tester", "tester@example.com")
    return str(repo.create_commit("HEAD", author, author, "c",
                                  builder.write(), parents))


def test_tree_files_projects_blob_heads(cache):
    repo = pygit2.init_repository(str(cache / "tree"))
    oid = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n",
                               "helper.sh": b"echo hi\n"}, [])
    result = gw._tree_files({"pkg": "tree", "cache_dir": str(cache), "oid": oid})
    assert result["complete"] is True
    by = {name: base64.b64decode(data) for name, data in result["files"]}
    assert set(by) == {"PKGBUILD", "helper.sh"}
    assert b"pkgver=1.0" in by["PKGBUILD"]


def test_opaque_changed_names_a_replaced_binary(cache):
    repo = pygit2.init_repository(str(cache / "opq"))
    old = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n", "blob.bin": b"A"}, [])
    new = _commit_files(repo, {"PKGBUILD": b"pkgver=1.0\n", "blob.bin": b"B"},
                        [pygit2.Oid(hex=old)])
    names = gw._opaque_changed({"pkg": "opq", "cache_dir": str(cache),
                                "old": old, "new": new})["names"]
    assert names == ["blob.bin"]


def test_companion_hunks_emit_a_named_file(cache):
    repo = pygit2.init_repository(str(cache / "comp"))
    oid = _commit_files(repo, {
        "PKGBUILD": b"pkgname=x\nsource=(\"helper.sh\")\n",
        "helper.sh": b"echo hi\n",
    }, [])
    out = gw._companion_hunks({"pkg": "comp", "cache_dir": str(cache),
                               "oid": oid, "max_bytes": None})
    assert "helper.sh" in out["text"]
    assert "echo hi" in out["text"]


def test_tree_files_reports_incomplete_when_capped(cache, monkeypatch):
    repo = pygit2.init_repository(str(cache / "many"))
    oid = _commit_files(repo, {f"f{i}": b"x\n" for i in range(3)}, [])
    monkeypatch.setattr(gw, "GIT_TREE_MAX_ENTRIES", 2)
    result = gw._tree_files({"pkg": "many", "cache_dir": str(cache), "oid": oid})
    assert result["complete"] is False
    assert len(result["files"]) == 2


def test_walk_and_commit_meta(cache):
    repo = pygit2.init_repository(str(cache / "hist"))
    c1 = _commit_files(repo, {"PKGBUILD": b"v1\n"}, [])
    c2 = _commit_files(repo, {"PKGBUILD": b"v2\n"}, [pygit2.Oid(hex=c1)])
    c3 = _commit_files(repo, {"PKGBUILD": b"v3\n"}, [pygit2.Oid(hex=c2)])

    commits = gw._walk({"pkg": "hist", "cache_dir": str(cache), "head": c3,
                        "limit": None})["commits"]
    assert {c["id"] for c in commits} == {c1, c2, c3}
    assert next(c for c in commits if c["id"] == c1)["parents"] == []

    meta = gw._commit_meta({"pkg": "hist", "cache_dir": str(cache),
                            "oids": [c1, c3]})["commits"]
    assert {m["id"] for m in meta} == {c1, c3}


def test_merge_parents_are_commit_ids_not_objects(cache):
    repo = pygit2.init_repository(str(cache / "m"))
    c1 = _commit_files(repo, {"PKGBUILD": b"v1\n"}, [])
    c2 = _commit_files(repo, {"PKGBUILD": b"v2\n"}, [pygit2.Oid(hex=c1)])
    tip = _commit_files(repo, {"PKGBUILD": b"v3\n"}, [pygit2.Oid(hex=c2)])
    merge = _commit_files(repo, {"PKGBUILD": b"m\n"},
                          [pygit2.Oid(hex=tip), pygit2.Oid(hex=c1)])
    rec = next(c for c in gw._walk({"pkg": "m", "cache_dir": str(cache),
                                    "head": merge, "limit": None})["commits"]
               if c["id"] == merge)
    assert rec["parents"] == [tip, c1]
    assert all(len(p) == 40 for p in rec["parents"])


def test_walk_treats_a_nonpositive_limit_as_empty(cache):
    repo = pygit2.init_repository(str(cache / "lim"))
    oid = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    for limit in (0, -5):
        assert gw._walk({"pkg": "lim", "cache_dir": str(cache),
                         "head": oid, "limit": limit})["commits"] == []


def test_walk_refuses_an_uncoercible_limit(cache):
    repo = pygit2.init_repository(str(cache / "wl"))
    oid = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    with pytest.raises(gw._OpError, match="invalid walk limit"):
        gw._walk({"pkg": "wl", "cache_dir": str(cache),
                  "head": oid, "limit": "abc"})


def test_file_at_refuses_a_non_string_oid(cache):
    repo = pygit2.init_repository(str(cache / "fa"))
    _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    with pytest.raises(gw._OpError, match="invalid commit id"):
        gw._file_at({"pkg": "fa", "cache_dir": str(cache), "oid": 123,
                     "name": "PKGBUILD"})


def test_commit_meta_skips_non_commit_objects(cache):
    repo = pygit2.init_repository(str(cache / "obj"))
    commit = _commit_files(repo, {"PKGBUILD": b"v\n"}, [])
    blob = str(repo.create_blob(b"x"))
    out = gw._commit_meta({"pkg": "obj", "cache_dir": str(cache),
                           "oids": [blob, commit]})["commits"]
    assert [c["id"] for c in out] == [commit]


def test_a_missing_repository_is_refused_cleanly(cache):
    with pytest.raises(gw._OpError, match="repository unavailable"):
        gw._walk({"pkg": "nope", "cache_dir": str(cache), "head": "0" * 40,
                  "limit": None})


def test_commit_meta_refuses_too_many_ids(cache):
    with pytest.raises(gw._OpError, match="too many"):
        gw._commit_meta({"pkg": "hist", "cache_dir": str(cache),
                         "oids": ["0" * 40] * 65})
