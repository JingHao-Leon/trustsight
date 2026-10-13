"""Shared launch of an isolated sandbox child.

Both sandboxes (the tokenizer worker and the git worker) start the same way:
an isolated interpreter (``-I``: no ``PYTHON*`` environment, no user site, no
cwd on ``sys.path``), a minimal environment (:func:`subproc.minimal_env`), a
new session, and an explicit import of the worker module whose ``main`` is
called.  One implementation, so a fix to the launch (the ``PYTHONPATH``
``sitecustomize`` finding) cannot reach only one of them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ..subproc import minimal_env

__all__ = ["launch_args", "spawn_isolated", "WORKER_ROOT"]


#: The directory a worker inserts on ``sys.path`` to import this package - the
#: tree this process already imported from, not a path an attacker chose.
WORKER_ROOT = str(Path(__file__).resolve().parents[2])


def launch_args(module: str) -> list[str]:
    """The child command line for worker *module* (dotted name).

    ``-I`` is isolated mode.  Isolation also means the child cannot find this
    package through the environment, so the bootstrap inserts the trusted
    source root explicitly and then calls the worker's ``main``.
    """
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {WORKER_ROOT!r});"
        f"import {module} as _worker;"
        "raise SystemExit(_worker.main())"
    )
    return [sys.executable, "-I", "-c", bootstrap]


def spawn_isolated(module: str, cwd: str = "/") -> subprocess.Popen:
    """Start worker *module* with stdio piped, a minimal env, own session."""
    return subprocess.Popen(
        launch_args(module),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        cwd=cwd,
        env=minimal_env(),
    )
