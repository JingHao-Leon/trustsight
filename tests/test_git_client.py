"""The isolated git client: subprocess transport, isolation and refusal (A16).

These run the real worker process against a local fixture repository (no
network), so they cover the framed channel, the isolated launch, and the
"a dead worker is a refusal" contract.
"""

from __future__ import annotations


import pygit2
import pytest

from trustsight.sandbox import git_client, _spawn


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / "repos"
    root.mkdir()
    repo = pygit2.init_repository(str(root / "demo"), bare=True)
    author = pygit2.Signature("Tester", "tester@example.com")
    blob = repo.create_blob(b"pkgver=7.7\n")
    builder = repo.TreeBuilder()
    builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
    repo.create_commit("refs/heads/master", author, author, "c",
                       builder.write(), [])
    return root


def test_head_and_file_at_round_trip(cache):
    session = git_client.GitSession()
    try:
        head = session.head("demo", str(cache))
        assert head
        text = session.file_at("demo", str(cache), head, "PKGBUILD", 4096)
        assert text == "pkgver=7.7\n"
    finally:
        session.close()


def test_an_unknown_member_is_refused_across_the_boundary(cache):
    session = git_client.GitSession()
    try:
        head = session.head("demo", str(cache))
        with pytest.raises(git_client.GitOpError):
            session.file_at("demo", str(cache), head, "../../etc/passwd", 4096)
    finally:
        session.close()


def test_a_closed_session_refuses(cache):
    session = git_client.GitSession()
    session.close()
    with pytest.raises(git_client.GitSandboxUnavailable):
        session.head("demo", str(cache))


def test_diff_round_trip(cache):
    repo = pygit2.init_repository(str(cache / "d"))
    author = pygit2.Signature("Tester", "tester@example.com")

    def commit(text, parents):
        blob = repo.create_blob(text)
        builder = repo.TreeBuilder()
        builder.insert("PKGBUILD", blob, pygit2.GIT_FILEMODE_BLOB)
        return str(repo.create_commit("HEAD", author, author, "c",
                                      builder.write(), parents))

    old = commit(b"pkgver=1.0\n", [])
    new = commit(b"pkgver=2.0\n", [pygit2.Oid(hex=old)])
    session = git_client.GitSession()
    try:
        out = session.diff("d", str(cache), old, new, context_lines=3)
    finally:
        session.close()
    assert "pkgver=2.0" in out["unified"]
    assert out["summary"]["files_changed"] == ["PKGBUILD"]


def test_the_worker_launch_is_isolated():
    args = _spawn.launch_args("trustsight.sandbox.git_worker")
    assert "-I" in args
    assert "-s" not in args
    assert "git_worker" in args[-1]


def test_the_worker_ignores_an_inherited_pythonpath(tmp_path, cache, monkeypatch):
    guard = tmp_path / "guard"
    guard.mkdir()
    sentinel = tmp_path / "sentinel"
    (guard / "sitecustomize.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(sentinel)!r}).write_text('pwned')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(guard))

    result = git_client.run_op("head", {"pkg": "demo", "cache_dir": str(cache)})
    assert result["head"]
    assert not sentinel.exists(), "the worker executed a PYTHONPATH sitecustomize"
