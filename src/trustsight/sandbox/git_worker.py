"""Child entry point for the isolated git sandbox (A16).

The only module under ``src/`` that imports ``pygit2``.  It is started by
``trustsight.sandbox.git_client`` as ``python -I -c <bootstrap>`` with a
minimal environment; it owns every libgit2 handle and answers a small set of
projection requests over the framed JSON protocol.  The parent never calls
libgit2, so a memory-safety defect in libgit2 (or in the bundled pack/delta
code) exhausts or kills this bounded child instead of the analysis.

Confinement, all fixed constants from :mod:`trustsight.sandbox.git_bounds`:

* ``RLIMIT_AS`` caps the address space, so a delta-result-size amplification
  exhausts the child, not the analysis process.
* ``RLIMIT_CPU`` and ``RLIMIT_FSIZE`` cap work and disk (unlike the tokenizer
  worker, this one writes the clone and the fetch marker).
* ``PR_SET_NO_NEW_PRIVS`` makes a defect here unable to gain privilege.
* The network is *kept* - the worker must reach the A3 AUR host - but the
  remote URL is built here from a validated package name, never received.
* libgit2 is configured with no user home, strict object creation and strict
  hash verification, and a fixed pack object ceiling.
"""

import atexit
import ctypes
import json
import os
import re
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pygit2

from trustsight.sandbox import protocol
from trustsight.sandbox.git_bounds import (
    GIT_PACK_MAX_OBJECTS,
    GIT_WORKER_CPU_SECONDS,
    GIT_WORKER_FSIZE_BYTES,
    GIT_WORKER_MEMORY_BYTES,
    GIT_WORKER_NOFILE,
)

_PR_SET_NO_NEW_PRIVS = 38

#: Package names, matching ``fetcher``.  Repeated rather than imported so the
#: worker's path validation does not depend on the parent's module state.
_VALID_PKG_NAME = re.compile(r"^[a-zA-Z0-9@._+\-]+$")
_RESERVED_PKG_NAMES = frozenset({".", ".."})

_FETCH_MARKER = "trustsight-last-fetch"

_AUR_HOST = "https://aur.archlinux.org"


class _UnknownOp(Exception):
    """The request named an operation the worker does not implement."""


class _OpError(Exception):
    """A worker operation could not complete."""


def _apply_limits() -> None:
    for which, value in (
        (resource.RLIMIT_AS, GIT_WORKER_MEMORY_BYTES),
        (resource.RLIMIT_CPU, GIT_WORKER_CPU_SECONDS),
        (resource.RLIMIT_FSIZE, GIT_WORKER_FSIZE_BYTES),
        (resource.RLIMIT_NOFILE, GIT_WORKER_NOFILE),
    ):
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError):
            pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _harden_libgit2() -> str:
    """Configure libgit2 once; return the throwaway HOME directory used.

    ``pygit2.settings`` has no setter for the config ``search_path`` in the
    pinned release, so system/XDG git config cannot be cleared from here; the
    user's own ``~/.gitconfig`` is removed by pointing ``homedir`` at an empty
    directory.  That still sits inside the model's trusted-local-filesystem
    assumption for the system path (recorded as a drift note).
    """
    home = tempfile.mkdtemp(prefix="trustsight-git-home-")
    atexit.register(shutil.rmtree, home, ignore_errors=True)
    try:
        pygit2.settings.homedir = home
    except (AttributeError, pygit2.GitError, ValueError):
        pass
    try:
        pygit2.settings.pack_max_objects = GIT_PACK_MAX_OBJECTS
    except (AttributeError, pygit2.GitError, ValueError):
        pass
    for enable in (
        pygit2.settings.enable_strict_object_creation,
        pygit2.settings.enable_strict_hash_verification,
    ):
        try:
            enable(True)
        except (AttributeError, pygit2.GitError, ValueError, TypeError):
            pass
    return home


def _contained_repo_path(cache_dir: str, pkg: str):
    """The repo path for *pkg* under *cache_dir*, or raise.

    The parent has already validated the name, but this is the value the
    worker ``rmtree``s and writes to, so it is checked again here.
    """
    if not isinstance(pkg, str) or not _VALID_PKG_NAME.match(pkg) \
            or pkg in _RESERVED_PKG_NAMES:
        raise _OpError(f"invalid package name: {pkg!r}")
    root = Path(cache_dir).resolve()
    path = (root / pkg).resolve()
    if path.parent != root:
        raise _OpError(f"package path escapes cache directory: {pkg!r}")
    return path


def _head_commit_id(repo) -> str:
    try:
        return str(repo.head.peel().id)
    except pygit2.GitError:
        pass
    if repo.head_is_unborn or repo.is_empty:
        return ""
    for name in ("main", "master"):
        try:
            return str(repo.branches[name].peel().id)
        except (KeyError, pygit2.GitError):
            pass
    for ref_name in repo.references:
        try:
            return str(repo.references[ref_name].peel().id)
        except (TypeError, pygit2.GitError):
            pass
    raise _OpError("cannot resolve HEAD to a commit")


def _last_fetch_time(repo):
    try:
        return int((Path(repo.path) / _FETCH_MARKER).read_text().strip())
    except (OSError, ValueError):
        return None


def _marker_path(repo):
    return Path(repo.path) / _FETCH_MARKER


def _record_fetch(repo):
    stamp = int(time.time())
    try:
        _marker_path(repo).write_text(str(stamp))
    except OSError:
        return None
    return stamp


def _is_current(repo, upstream_mtime) -> bool:
    fetched = _last_fetch_time(repo)
    if fetched is not None:
        try:
            return fetched >= int(upstream_mtime)
        except (TypeError, ValueError):
            return False
    try:
        return int(repo.head.peel().commit_time) >= int(upstream_mtime)
    except (AttributeError, pygit2.GitError, KeyError, TypeError, ValueError):
        return False


def _advance_to_fetched_head(repo) -> None:
    try:
        if repo.head_is_unborn or repo.head_is_detached:
            local_name = None
        else:
            local_name = repo.head.shorthand
    except pygit2.GitError:
        local_name = None
    remote_ref_name = None
    if local_name:
        candidate = f"refs/remotes/origin/{local_name}"
        if candidate in repo.references:
            remote_ref_name = candidate
    if remote_ref_name is None:
        origin_head = repo.references.get("refs/remotes/origin/HEAD")
        symbolic = getattr(origin_head, "symbolic_target", None) if origin_head else None
        if symbolic:
            remote_ref_name = symbolic
    if remote_ref_name is None:
        return
    remote_ref = repo.references.get(remote_ref_name)
    target = getattr(remote_ref, "target", None)
    if target is None:
        return
    branch_ref = (
        repo.references.get(f"refs/heads/{local_name}") if local_name else None
    )
    if branch_ref is not None:
        branch_ref.set_target(target)
    else:
        repo.set_head(remote_ref_name)


class _Callbacks(pygit2.RemoteCallbacks):
    """Abort a transfer that runs past a deadline without any progress."""

    def __init__(self, seconds: int):
        super().__init__()
        self._deadline = time.monotonic() + seconds

    def _check(self):
        if time.monotonic() > self._deadline:
            raise _OpError("fetch timed out")

    def transfer_progress(self, stats):
        self._check()

    def sideband_progress(self, string):
        self._check()


def _open_fetch(payload: dict) -> dict:
    pkg = payload.get("pkg", "")
    cache_dir = payload.get("cache_dir", "")
    upstream_mtime = payload.get("upstream_mtime")
    offline = bool(payload.get("offline"))
    connect = int(payload.get("connect_timeout", 10) or 10)
    transfer = int(payload.get("transfer_timeout", 30) or 30)

    path = _contained_repo_path(cache_dir, pkg)
    try:
        pygit2.settings.server_connect_timeout = connect * 1000
        pygit2.settings.server_timeout = transfer * 1000
    except (AttributeError, pygit2.GitError, ValueError):
        pass

    if path.exists():
        cached = None
        try:
            cached = pygit2.Repository(str(path))
            if not _head_commit_id(cached):
                raise pygit2.GitError("cached clone has no commits")
        except (pygit2.GitError, _OpError):
            shutil.rmtree(path, ignore_errors=True)
            cached = None
        if cached is not None:
            if upstream_mtime is not None and _is_current(cached, upstream_mtime):
                return {"path": str(path), "head": _head_commit_id(cached),
                        "fetched": False, "marker_time": _last_fetch_time(cached)}
            if offline:
                return {"path": str(path), "head": _head_commit_id(cached),
                        "fetched": False, "marker_time": _last_fetch_time(cached)}
            cached.remotes["origin"].fetch(callbacks=_Callbacks(120))
            _advance_to_fetched_head(cached)
            return {"path": str(path), "head": _head_commit_id(cached),
                    "fetched": True, "marker_time": _record_fetch(cached)}

    if offline:
        raise _OpError(
            "TRUSTSIGHT_OFFLINE is set and no cached clone exists for "
            f"{pkg!r}: refusing to clone from the AUR"
        )
    os.makedirs(path.parent, exist_ok=True)
    url = f"{_AUR_HOST}/{pkg}.git"
    repo = pygit2.clone_repository(url, str(path), bare=True,
                                   callbacks=_Callbacks(120))
    return {"path": str(path), "head": _head_commit_id(repo),
            "fetched": True, "marker_time": _record_fetch(repo)}


def _head(payload: dict) -> dict:
    path = _contained_repo_path(payload.get("cache_dir", ""), payload.get("pkg", ""))
    repo = pygit2.Repository(str(path))
    return {"head": _head_commit_id(repo)}


def _file_at(payload: dict) -> dict:
    """The body of one named top-level file at a commit, as text."""
    name = payload.get("name", "")
    if name not in ("PKGBUILD", ".SRCINFO"):
        raise _OpError(f"file_at refuses unknown member: {name!r}")
    oid = payload.get("oid") or ""
    max_bytes = int(payload.get("max_bytes") or 5 * 1024 * 1024)
    path = _contained_repo_path(payload.get("cache_dir", ""), payload.get("pkg", ""))
    repo = pygit2.Repository(str(path))
    commit = repo.get(oid) if oid else None
    if commit is None:
        return {"text": ""}
    try:
        blob = commit.tree[name]
    except KeyError:
        return {"text": ""}
    if getattr(blob, "size", 0) > max_bytes:
        raise _OpError(f"{name} exceeds {max_bytes} bytes")
    return {"text": blob.data.decode("utf-8", errors="replace")}


def _diff(payload: dict) -> dict:
    """Two commits' metadata-file diff, as text plus a serialised summary.

    Reuses ``differ.generate_diff_bounded`` so the parent's current in-process
    result and the isolated one cannot drift: the same code builds the patch
    text, applies the same caps, and selects the same files.
    """
    from trustsight.differ import generate_diff_bounded

    old = payload.get("old") or ""
    new = payload.get("new") or ""
    context = int(payload.get("context_lines", 3) or 3)
    max_bytes = payload.get("max_bytes")
    path = _contained_repo_path(payload.get("cache_dir", ""), payload.get("pkg", ""))
    repo = pygit2.Repository(str(path))
    text, summary, truncated = generate_diff_bounded(
        repo, old, new, context_lines=context, max_bytes=max_bytes)
    return {
        "unified": text,
        "summary": {
            "lines_added": summary.lines_added,
            "lines_removed": summary.lines_removed,
            "files_changed": list(summary.files_changed),
            "file_changes": [dict(entry) for entry in summary.file_changes],
        },
        "truncated": bool(truncated),
    }


_DISPATCH = {
    "open_fetch": _open_fetch,
    "head": _head,
    "file_at": _file_at,
    "diff": _diff,
}


def _handle(body: bytes) -> dict:
    try:
        request = json.loads(body.decode("utf-8"))
        fn = _DISPATCH.get(request.get("op"))
        if fn is None:
            raise _UnknownOp(f"unknown op: {request.get('op')!r}")
        return {"result": fn(request)}
    except _UnknownOp as exc:
        return {"error": str(exc)}
    except _OpError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # a defect is a refusal, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    _apply_limits()
    _harden_libgit2()
    try:
        os.chdir("/")
    except OSError:
        pass
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        try:
            body = protocol.read_frame(stdin)
        except protocol.FrameError:
            return 0
        stdout.write(protocol.frame(json.dumps(
            _handle(body), separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")))
        stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
