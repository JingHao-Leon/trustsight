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

from ..rules import ScopeResolver
from ..tokenizer import resolve_added_lines
from .build import _recipe_lines
from .delivery import (
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
    EdgeInstance("H072", "Write Then Execute", "write", "exec", None, (), "HIGH",
                 "docs/reference/rules/fetch-and-execution.md",
                 ("tests/test_phase2.py",),
                 edge_write_execute),
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
)


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
