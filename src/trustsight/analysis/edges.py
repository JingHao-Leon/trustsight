"""The edge engine: the resolved pipeline as shared facts (Addendum 3 §Phase 3).

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
from ..rules import ScopeResolver
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
    _declared_source_urls,
    _foreign_declared_source_bases,
    _heredoc_body_indices,
    edge_fetch_then_execute,
    edge_source_file_execution,
    edge_unread_execution,
    edge_write_execute,
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
    #: Basenames of declared sources fetched from a foreign host.
    foreign_declared_bases: frozenset[str] = field(default_factory=frozenset)
    #: Normalized URLs the declared ``source=()`` array carries.
    declared_urls: frozenset[str] = field(default_factory=frozenset)
    #: H016's declared set: the post-diff PKGBUILD where the caller has it,
    #: the diff otherwise (the declaration routinely sits outside the hunk).
    declared_urls_full: frozenset[str] = field(default_factory=frozenset)
    #: Canonical hosts named by the declared sources.
    declared_hosts: frozenset[str] = field(default_factory=frozenset)


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
        foreign_declared_bases=_foreign_declared_source_bases(diff_text, current_text),
        declared_urls=_declared_source_urls(diff_text),
        declared_urls_full=frozenset(normalize_url(u) for u in declared_src),
        declared_hosts=frozenset(
            canonical_host(u.split("://", 1)[1].split("/", 1)[0])
            for u in declared_src if "://" in u
        ),
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
                 ("tests/test_phase3.py",),
                 edge_recon),
    EdgeInstance("H041", "Upload To Paste Or File-Drop Host", "fetch", "upload",
                 None, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_gap_rules.py",),
                 edge_paste_egress),
    EdgeInstance("H042", "Hidden Drop", "write", None, None, (), "HIGH",
                 "docs/reference/rules/staging-and-recon.md",
                 ("tests/test_phase3.py",),
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
                 ("tests/test_phase2.py",),
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
