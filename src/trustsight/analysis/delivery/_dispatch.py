"""Extracted from delivery.py: _dispatch."""

from ...config import (
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ._buildtree import _committed_execution_findings
from ._payloads import _reconstructed_payload_findings
from ._recon import _anti_analysis_findings
from ._unread import _unverifiable_findings

__all__ = ['_delivery_findings']

def _delivery_findings(
    diff_text, config, add, tree_manifest=None, current_text=None, ctx=None
) -> None:
    """Run the diff-text rules (H067-H069, H072, H081-H085) through *add*.

    *current_text* is the PKGBUILD as it now stands, used only to build the
    call graph: a helper added by this diff may be called from a ``build()``
    that the hunk does not show. *ctx* is the shared graph context;
    it is built here only when the caller did not supply one.
    """
    from ..edges import build_context, run_edge_instances
    from ..persistence_engine import run_persistence_instances

    if ctx is None:
        ctx = build_context(diff_text, config, current_text=current_text,
                            tree_manifest=tree_manifest)
    _anti_analysis_findings(diff_text, config, add, current_text=current_text)
    _reconstructed_payload_findings(diff_text, config, add)
    run_edge_instances(ctx, add, only=frozenset({"H072"}))
    run_edge_instances(ctx, add, only=frozenset({"H082"}))
    run_edge_instances(ctx, add, only=frozenset({"H083"}))
    run_edge_instances(ctx, add, only=frozenset({"X033"}))
    run_persistence_instances(ctx, add, only=frozenset({"H084"}))
    run_persistence_instances(ctx, add, only=frozenset({"H085"}))
    _committed_execution_findings(
        diff_text, tree_manifest, add, current_text=current_text,
    )
    run_persistence_instances(ctx, add, only=frozenset({"H089"}))
    run_persistence_instances(ctx, add, only=frozenset({"H095"}))
    _unverifiable_findings(diff_text, config, add,
                           tree_manifest=tree_manifest,
                           current_text=current_text, ctx=ctx)
