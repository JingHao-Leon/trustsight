"""Addendum 3 Phase 3: the edge engine's shared context and predicates."""

from pathlib import Path

from trustsight.analysis.edges import (
    EDGE_INSTANCES,
    GraphContext,
    build_context,
    run_edge_instances,
)
from trustsight.analysis.pipeline import scan_diff

ROOT = Path(__file__).resolve().parent.parent


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(body: str) -> set[str]:
    fact = scan_diff(_diff(body), package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def test_edge_instances_register_h094():
    registered = {instance.rule_id: instance for instance in EDGE_INSTANCES}
    assert "H094" in registered
    assert registered["H094"].emitter is not None
    assert (ROOT / registered["H094"].doc).exists()
    for fixture in registered["H094"].fixtures:
        assert (ROOT / fixture).exists()


def test_build_context_computes_the_shared_facts():
    ctx = build_context(_diff("build() {\n  ./x.sh\n}\n"), {})
    assert isinstance(ctx, GraphContext)
    assert ctx.lines
    assert ctx.scopes is not None


def test_unread_execution_predicate_fires_in_package_scope():
    assert "H094" in _ids("package() {\n  ./x.sh\n}\n")


def test_unread_execution_predicate_reports_w001_in_build_scope():
    assert "W001" in _ids("build() {\n  ./x.sh\n}\n")


def test_run_edge_instances_is_scoped_by_rule():
    ctx = build_context(_diff("package() {\n  ./x.sh\n}\n"), {})
    seen: list[str] = []

    def add(rule_id, *_args, **_kwargs):
        seen.append(rule_id)

    run_edge_instances(ctx, add, only=frozenset({"H094"}))
    assert seen == ["H094"]
