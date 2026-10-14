"""Extracted from differ.py: _diff."""

from ..diffdoc import parse_diff_lines, strip_diff_path_prefix
from ..schema import DiffSummary
from ..tokenizer import split_lines
from ._bounds import MAX_DIFF_BYTES, MAX_DIFF_PATH_BYTES

__all__ = ['_bounded_path', '_diff_file_path', 'diff_summary_from_text', 'generate_diff', 'generate_diff_bounded', 'map_diff_lines', 'truncate_diff']

def truncate_diff(diff_text: str, max_bytes: int = MAX_DIFF_BYTES) -> tuple[str, bool]:
    """Return a deterministic UTF-8-safe prefix and truncation status."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    max_bytes = min(max_bytes, MAX_DIFF_BYTES)
    encoded = diff_text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return diff_text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True

def map_diff_lines(diff_text: str) -> dict[int, tuple[str, int]]:
    """Map diff-line index → (file_name, new_file_line_number).

    Returns a dict keyed by the 0-based line index into *diff_text*'s
    lines, with each value being ``(file_name, line_number)``.
    Only content lines (`` `` context, ``+`` addition, ``-`` removal)
    produce entries; header lines are not mapped.

    A projection of the typed parse (:mod:`trustsight.diffdoc`): the
    file attribution, the hunk gating and the line counter are the
    parser's decisions now, made once, and the committed projection
    baseline pins the shape over the whole locked corpus.
    """
    return parse_diff_lines(split_lines(diff_text)).line_map()

def _bounded_path(path: str) -> str:
    """A path bounded for retention in a summary."""
    encoded = path.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_DIFF_PATH_BYTES:
        return path
    return encoded[:MAX_DIFF_PATH_BYTES].decode("utf-8", errors="ignore")

def generate_diff_bounded(
    repo, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary, bool]:
    """Generate a unified diff, and say whether anything was dropped.

    The libgit2 work lives in :mod:`trustsight.sandbox.git_project` (A16); the
    production path reaches it through a ``GitSession``, and a fixture
    repository is handled in-process for tests.
    """
    from ..sandbox.git_project import generate_diff_bounded as _core

    return _core(repo, old_oid, new_oid, context_lines, max_bytes)

def generate_diff(
    repo, old_oid: str, new_oid: str, context_lines: int = 3,
    max_bytes: int | None = None,
) -> tuple[str, DiffSummary]:
    """Two-value form, for callers that do not consume the truncation flag."""
    text, summary, _truncated = generate_diff_bounded(
        repo, old_oid, new_oid, context_lines, max_bytes
    )
    return text, summary

def diff_summary_from_text(diff_text: str) -> DiffSummary:
    """Build a ``DiffSummary`` from raw unified-diff text.

    The git producer reads ``diff.deltas`` for its file list and ``diff.stats``
    for its line counts.  The text producers (``scan_diff`` and the corpus
    adapter) counted ``+``/``-`` lines with ``startswith``, which also counts
    the ``+++``/``---`` headers, and never populated ``files_changed`` /
    ``file_changes`` at all.  That made ``is_trivial`` return True on the text
    path for any change whatsoever - a diff adding an untrusted source URL
    read as a trivial update - and dropped the "new file"/"file removed"
    summary entries.  One construction serves every producer now.
    """
    if not diff_text:
        return DiffSummary()

    files_changed: set[str] = set()
    file_changes: list[dict] = []
    seen: set[str] = set()
    lines_added = 0
    lines_removed = 0

    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith("+++ "):
            path = _diff_file_path(raw[4:])
            # `+++ /dev/null` is a deletion, not a path: recording it put
            # the literal string "/dev/null" in files_changed, and the
            # added/removed fix-up below could never find it there.
            if path and path != "/dev/null" and path not in seen:
                seen.add(path)
                if path not in (".SRCINFO", ".gitignore"):
                    file_changes.append({"path": path, "status": "modified"})
                files_changed.add(path)
            continue
        if raw.startswith("--- ") or raw.startswith("@@"):
            continue
        if line.side == "add":
            lines_added += 1
        elif line.side == "remove":
            lines_removed += 1

    # Statuses the text diff cannot express in one line: a path that has only
    # a `+++ b/...` side is added, one that has only a `--- a/...` side is
    # removed.
    old_paths: set[str] = set()
    new_paths: set[str] = set()
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith("--- ") and not raw.startswith("--- /dev/null"):
            old_paths.add(_diff_file_path(raw[4:]))
        elif raw.startswith("+++ ") and not raw.startswith("+++ /dev/null"):
            new_paths.add(_diff_file_path(raw[4:]))
    added_paths = new_paths - old_paths
    removed_paths = old_paths - new_paths
    for entry in file_changes:
        if entry["path"] in added_paths:
            entry["status"] = "added"
    # A deleted file has no `+++` side to record in the first loop - its
    # only header is `--- a/path` opposite `+++ /dev/null` - so it enters
    # the summary here, already marked removed.  The git producer path
    # reads the same fact from the delta's `old_file.path`.
    for path in removed_paths - seen:
        seen.add(path)
        if path not in (".SRCINFO", ".gitignore"):
            file_changes.append({"path": path, "status": "removed"})
        files_changed.add(path)

    file_changes.sort(key=lambda item: (item["path"], item["status"]))
    return DiffSummary(
        lines_added=lines_added,
        lines_removed=lines_removed,
        files_changed=sorted(files_changed),
        file_changes=file_changes,
    )

def _diff_file_path(header: str) -> str:
    """The path from a `---`/`+++` header, git's path prefix stripped.

    The prefix may be a mnemonic one (`c/` for a commit diff) when the
    reviewer's git config sets `diff.mnemonicprefix`; `strip_diff_path_prefix`
    handles both spellings.
    """
    path = header.strip()
    if "\t" in path:
        path = path.split("\t", 1)[0]
    return strip_diff_path_prefix(path)
