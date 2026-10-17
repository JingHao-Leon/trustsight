"""The edge engine: the resolved pipeline as shared facts (§).

Fourteen H rules walk the same resolved diff: each rebuilds
``resolve_added_lines``, a ``ScopeResolver``, the heredoc body set and the
declared-source basename set, then pairs a source fact with a sink fact under
a function scope.  :class:`GraphContext` computes those facts **once** and the
:data:`EDGE_INSTANCES` table records each rule as a predicate over them.

This module owns the context and the dispatch; the predicates live beside the
catalogs they need (delivery/build/network/…) and are registered here.  The
rule ids, severities and finding text are unchanged - the locked-corpus replay
and the regression suites are the byte-identical gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..buckets import canonical_host
from ..differ import extract_source_array_urls, urls_from_pkgbuild_text
from ..diffdoc import parse_diff_lines
from ..findings import stamp
from ..novelty import normalize_url
from ..recipedoc import parse_recipe
from ..rules import ScopeResolver
from ..rules import _classify_line_context
from ..tokenizer import resolve_added_lines, split_lines


from .build import (
    _recipe_lines,
    edge_foreign_pkg,
    edge_hidden_fetch,
    edge_indirect_expansion,
    edge_indirect_remote_execution,
)
from .composition import edge_recon
from .network import (
    edge_covert_egress,
    edge_parse_time_fetch,
    edge_paste_egress,
)
from .persistence import edge_hidden_drop
from .delivery import (
    _COMMITTED_CARRIER_RE,
    _COMMITTED_PAYLOAD_RE,
    _declared_source_basenames,
    _declared_extraction_dirs,
    _declared_source_urls,
    _unpinned_source_basenames,
    _heredoc_body_indices,
    _printed_heredoc_body_indices,
    edge_fetch_then_execute,
    edge_source_file_execution,
    edge_undeclared_provenance_execution,
    edge_unread_execution,
    edge_write_execute,
)


def _declared_install_basename(
    diff_text: str, current_text: str | None,
) -> tuple[str, bool] | None:
    """The basename ``install=`` declares.

    Returns ``None`` when the declaration carries a variable - it declares
    *something* whose basename cannot be compared, so callers must not
    gate on it.  Otherwise ``(basename, certain)``: ``certain`` is False
    when neither the complete recipe nor any diff line shows the
    declaration - a fragment whose hunks miss the line is *unknown*, not
    absent, and behavior rules must keep firing rather than stand down on a
    guess.  The complete recipe is authoritative when the caller has it;
    added or context lines of the diff otherwise.
    """
    declared = ""
    certain = False
    if current_text:
        try:
            declared = parse_recipe(current_text).scalars.get("install", "")
            certain = True
        except Exception:  # noqa: BLE001 - a refusal keeps the diff read
            declared = ""
    if not certain:
        # Read through the typed core: a raw split_lines loop here is what
        # the adoption gate exists to prevent.  Only PKGBUILD lines count:
        # an .install hook or a patch can carry `install=`-shaped text that
        # is not the recipe's declaration, and misreading it would stand
        # behavior rules down on a live hook.  Lines with no file
        # attribution (a bare fragment) stay eligible.
        try:
            doc = parse_diff_lines(split_lines(diff_text))
        except Exception:  # noqa: BLE001 - an unreadable diff declares nothing
            doc = None
        for line in (doc.lines if doc else []):
            if line.side == "remove":
                continue
            if line.file and not line.file.endswith("PKGBUILD"):
                continue
            stripped = line.content.strip()
            if stripped.startswith("install=") or stripped.startswith("install ="):
                declared = stripped.split("=", 1)[1].strip().strip("\"'")
                certain = True
                break
    if not certain:
        return ("", False)
    if "$" in declared:
        return None
    return (declared.rsplit("/", 1)[-1], True)


def _dead_hook_files(
    line_files: dict[int, str], declared: tuple[str, bool] | None,
) -> frozenset[str]:
    """``.install`` paths pacman will never run.

    Behavior rules (H017, X015) must not claim work scheduled or privileged
    setup in a hook the recipe does not wire up: C024 already names that nit
    once, and a dead hook does nothing.  ``declared=None`` (variable
    declaration) declares an unknown file and ``("", False)`` means the
    declaration could not be seen at all; neither is positive evidence of a
    dead hook, so only a certain declaration gates.
    """
    if declared is None:
        return frozenset()
    base, certain = declared
    if not certain:
        return frozenset()
    return frozenset(
        path for path in set(line_files.values())
        if path.endswith(".install") and path.rsplit("/", 1)[-1] != base
    )


@dataclass
class GraphContext:
    """The resolved pipeline facts, computed once per analysis.

    Every field here was previously rebuilt per rule family; the counts
    (fourteen families) are why the duplication was worth removing.
    """

    diff_text: str
    config: dict
    current_text: str | None = None
    tree_manifest: list[tuple[str, bytes]] | None = None
    whole_recipe: bool = False

    #: Diff-shaped resolved lines (added lines carry their resolved form).
    lines: list[str] = field(default_factory=list)
    #: The shared scope resolver over those lines plus the current recipe.
    scopes: ScopeResolver | None = None
    #: Indices of literal heredoc body lines (data, not commands).
    heredoc_body: set[int] = field(default_factory=set)
    #: Basenames that arrive via the declared ``source=()`` array.
    source_basenames: set[str] = field(default_factory=set)
    #: Directories the declared source archives extract to under
    #: ``$srcdir`` (archive name minus one archive suffix; VCS clone dirs).
    extraction_dirs: set[str] = field(default_factory=set)
    #: Of those, the ones with no real checksum (``SKIP`` or no array):
    #: content the host decides at fetch time, which is H083's target.
    unpinned_source_basenames: frozenset = field(default_factory=frozenset)
    #: Normalized URLs the declared ``source=()`` array carries.
    declared_urls: frozenset[str] = field(default_factory=frozenset)
    #: H016's declared set: the post-diff PKGBUILD where the caller has it,
    #: the diff otherwise (the declaration routinely sits outside the hunk).
    declared_urls_full: frozenset[str] = field(default_factory=frozenset)
    #: Canonical hosts named by the declared sources.
    declared_hosts: frozenset[str] = field(default_factory=frozenset)
    #: Per-line comment/message context (``_classify_line_context``), shared
    #: by the install-hook predicates (H017, H035) instead of each computing
    #: it.
    line_context: dict = field(default_factory=dict)
    #: Indices of heredoc bodies that only *print* (message context).
    printed_heredoc: frozenset[int] = field(default_factory=frozenset)
    #: Which file each diff line belongs to (``+++ b/...`` attribution).
    line_files: dict[int, str] = field(default_factory=dict)
    #: ``.install`` paths the recipe does not wire up via ``install=``:
    #: pacman never runs them, so behavior claims inside them stand down.
    dead_hook_files: frozenset[str] = field(default_factory=frozenset)


def _line_file_map(lines: list[str]) -> dict[int, str]:
    """Map each diff-line index to its ``+++ b/...`` file path."""
    try:
        doc = parse_diff_lines(split_lines("\n".join(lines)))
    except Exception:  # noqa: BLE001 - unattributed lines gate nothing
        return {}
    out: dict[int, str] = {}
    for idx, line in enumerate(doc.lines):
        if line.file:
            out[idx] = line.file
    return out


def build_context(
    diff_text: str,
    config: dict,
    *,
    current_text: str | None = None,
    tree_manifest: list[tuple[str, bytes]] | None = None,
    whole_recipe: bool = False,
) -> GraphContext:
    """Compute the shared pipeline facts exactly once."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    line_files = _line_file_map(lines)
    declared_src = (
        urls_from_pkgbuild_text(current_text)
        if current_text
        else extract_source_array_urls(diff_text)
    )
    return GraphContext(
        diff_text=diff_text,
        config=config,
        current_text=current_text,
        tree_manifest=tree_manifest,
        whole_recipe=whole_recipe,
        lines=lines,
        scopes=scopes,
        heredoc_body=_heredoc_body_indices(lines),
        source_basenames=_declared_source_basenames(diff_text, current_text),
        extraction_dirs=_declared_extraction_dirs(diff_text, current_text),
        unpinned_source_basenames=_unpinned_source_basenames(diff_text, current_text),
        declared_urls=_declared_source_urls(diff_text),
        declared_urls_full=frozenset(normalize_url(u) for u in declared_src),
        declared_hosts=frozenset(
            canonical_host(u.split("://", 1)[1].split("/", 1)[0])
            for u in declared_src if "://" in u
        ),
        line_context=_classify_line_context(lines),
        printed_heredoc=frozenset(_printed_heredoc_body_indices(lines)),
        line_files=line_files,
        dead_hook_files=_dead_hook_files(
            line_files, _declared_install_basename(diff_text, current_text)),
    )


@dataclass(frozen=True)
class EdgeInstance:
    """One rule's predicate row over the graph context."""

    rule_id: str
    name: str
    src_class: str
    dst_class: str | None
    declared: bool | None
    scope: tuple[str, ...]
    severity: str
    doc: str
    fixtures: tuple[str, ...]
    emitter: Callable[[GraphContext, Callable], None] | None = None


#: The 14 Phase-3 rules.  Rows are filled in as their predicate is migrated;
#: an emitter of ``None`` means the rule still runs on its own walker.
EDGE_INSTANCES: tuple[EdgeInstance, ...] = (
    EdgeInstance("H040", "Host Reconnaissance", "recon", None, None, (), "INFO",
                 "docs/reference/rules/staging-and-recon.md",
                 ("tests/test_persistence_rules.py",),
                 edge_recon),
    EdgeInstance("H041", "Upload To Paste Or File-Drop Host", "fetch", "upload",
                 None, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_gap_rules.py",),
                 edge_paste_egress),
    EdgeInstance("H042", "Hidden Drop", "write", None, None, (), "HIGH",
                 "docs/reference/rules/staging-and-recon.md",
                 ("tests/test_persistence_rules.py",),
                 edge_hidden_drop),
    EdgeInstance("H016", "Hidden Network Fetch In Build", "fetch", None, False,
                 (), "HIGH", "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_deps_rules.py",),
                 edge_hidden_fetch),
    EdgeInstance("H035", "Foreign Package Manager In Install Hook",
                 "foreign_pkg", "install_hook", None, (), "HIGH",
                 "docs/reference/rules/install-and-persist.md",
                 ("tests/test_deps_rules.py",),
                 edge_foreign_pkg),
    EdgeInstance("H072", "Write Then Execute", "write", "exec", None, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_delivery_stack_rules.py",),
                 edge_write_execute),
    EdgeInstance("H075", "Remote Script Via Process Substitution", "fetch",
                 "shell", None, (), "CRITICAL",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_rules.py",),
                 edge_indirect_remote_execution),
    EdgeInstance("H080", "Indirect Command Expansion", "fetch", None, None, (),
                 "CRITICAL", "docs/reference/rules/crossfire.md",
                 ("tests/test_gap_rules.py",),
                 edge_indirect_expansion),
    EdgeInstance("H071", "Covert Egress", "covert_client", None, None, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_network.py",),
                 edge_covert_egress),
    EdgeInstance("H077", "Parse-time Network Fetch", "fetch", None, None, (),
                 "HIGH", "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_gap_rules.py",),
                 edge_parse_time_fetch),
    EdgeInstance("H082", "Fetch Then Execute", "fetch", "exec", None, (), "CRITICAL",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_evasion_regressions.py",),
                 edge_fetch_then_execute),
    EdgeInstance("H083", "Downloaded Source File Executed", "declared_source",
                 "exec", True, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_evasion_regressions.py",),
                 edge_source_file_execution),
    EdgeInstance("X033", "File With No Provenance Executed", "undeclared_source",
                 "exec", True, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_evasion_regressions.py",),
                 edge_undeclared_provenance_execution),
    EdgeInstance("H094", "Unread Script Executed During Packaging", "unread",
                 "packaging_exec", False, ("package",), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/regressions/test_w_series.py",),
                 edge_unread_execution),
    # H090 is manifest-scope, not diff-scope: its emitter runs over the
    # committed tree, so the row documents the predicate and the emitter is
    # `edge_committed_payload` (called by `scan_tree_manifest`).
    EdgeInstance("H090", "Committed Companion Carries A Fetch-Execute Payload",
                 "committed", "exec", True, (), "CRITICAL",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/regressions/test_w_series.py",),
                 None),
)


def edge_committed_payload(name: str, head: bytes) -> dict | None:
    """H090 predicate over one committed manifest entry.

    A committed unit, rule, hook or patch whose content fetches and runs
    code.  A patch is read by its *added* lines: a hunk that removes a
    ``curl … | sh`` is the opposite of this rule's subject.
    """
    if not _COMMITTED_CARRIER_RE.search(name.rstrip("/")):
        return None
    try:
        text = head.decode("utf-8", errors="replace")
    except Exception:
        return None
    if name.lower().endswith((".patch", ".diff")):
        text = "\n".join(
            ln.content for ln in parse_diff_lines(split_lines(text)).lines
            if ln.side == "add" and not ln.raw.startswith("+++")
        )
    m = _COMMITTED_PAYLOAD_RE.search(text)
    if not m:
        return None
    return stamp({
        "rule_id": "H090",
        "name": "Committed Companion Carries A Fetch-Execute Payload",
        "severity": "CRITICAL", "category": "delivery",
        "match": f"{name} downloads and runs code: {m.group(0).strip()[:80]}",
        "file": name,
        "params": {"path": name, "body": m.group(0).strip()[:120]},
    })


def run_edge_instances(
    ctx: GraphContext,
    add: Callable,
    *,
    only: frozenset[str] | None = None,
) -> None:
    """Dispatch the migrated edge predicates over *ctx*."""
    for instance in EDGE_INSTANCES:
        if instance.emitter is None:
            continue
        if only is not None and instance.rule_id not in only:
            continue
        instance.emitter(ctx, add)
