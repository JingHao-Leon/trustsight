"""Fixed bounds for the isolated git sandbox (A14: source constants).

Every limit the git worker enforces is a literal here, not a function of the
input, so a hostile repository cannot choose how much memory, CPU or disk the
worker spends before the parent kills it.  The parent reads the same module
for the values it needs at the boundary (timeouts), so the two sides cannot
disagree.
"""

from __future__ import annotations

__all__ = [
    "GIT_WORKER_MEMORY_BYTES",
    "GIT_WORKER_CPU_SECONDS",
    "GIT_WORKER_RETIRE_CPU_SECONDS",
    "GIT_WORKER_FSIZE_BYTES",
    "GIT_WORKER_NOFILE",
    "GIT_PACK_MAX_OBJECTS",
    "GIT_FETCH_TIMEOUT_SECONDS",
    "GIT_OP_TIMEOUT_SECONDS",
]

#: Address-space ceiling for one git worker.  AUR repositories are recipe
#: sized; 1 GiB is far above any legitimate clone and far below the analysis
#: process, so a libgit2 allocation amplification exhausts the child.
GIT_WORKER_MEMORY_BYTES = 1024 * 1024 * 1024

#: Wall-CPU ceiling before the kernel kills the child.
GIT_WORKER_CPU_SECONDS = 60

#: Cumulative CPU after which the parent retires a worker, below the hard
#: ceiling, so the kill is attributed to the worker not to the next request.
GIT_WORKER_RETIRE_CPU_SECONDS = 45

#: Largest file the child may write.  It clones and writes the fetch marker,
#: so this cannot be 0 (unlike the tokenizer worker); it bounds the expanded
#: pack on disk to well above ``fetcher.MAX_TRANSFER_BYTES``.
GIT_WORKER_FSIZE_BYTES = 512 * 1024 * 1024

#: Descriptors the child may hold.
GIT_WORKER_NOFILE = 64

#: Objects one pack may declare.  Bounds the object inventory the way
#: ``fetcher.MAX_HISTORY_COMMITS`` bounds the commit walk.
GIT_PACK_MAX_OBJECTS = 1_000_000

#: Wall-clock ceiling for the clone/fetch request, matching the existing
#: 120-second deadline plus startup and index time.
GIT_FETCH_TIMEOUT_SECONDS = 180

#: Wall-clock ceiling for a local object/diff request.
GIT_OP_TIMEOUT_SECONDS = 60

#: Context lines a diff request may ask for.  The analysis uses 3; a caller
#: cannot make the worker build an arbitrarily wide patch.
GIT_DIFF_MAX_CONTEXT_LINES = 200

#: Files one tree projection may return.  A recipe commits tens of files; a
#: repository can commit millions, so the projection is capped and reports
#: incomplete rather than building an unbounded list (the byte budget does
#: not bound the entry count).
GIT_TREE_MAX_ENTRIES = 100_000

#: Commit ids one ``commit_meta`` request may name.
GIT_COMMIT_META_MAX_OIDS = 64
