"""P009 prebuilt-deliverable declaration and its M001 contradiction."""

from __future__ import annotations

from trustsight.analysis.meta import claim_contradictions
from trustsight.scoring import (
    P_PREBUILT,
    calculate_score,
    declared_claims,
    prebuilt_declared,
)
from trustsight.schema import NoveltyContext


def _recipe(name: str, source: str = "") -> str:
    src = f'source=("{source}")\n' if source else ""
    return (
        f"pkgname={name}\npkgver=1\npkgrel=1\narch=(any)\n{src}"
        "package() { :; }\n"
    )


def test_bin_suffix_declares_prebuilt():
    assert prebuilt_declared(_recipe("foo-bin"))


def test_appimage_and_deb_source_declare_prebuilt():
    assert prebuilt_declared(_recipe("foo", "https://x/foo.AppImage"))
    assert prebuilt_declared(_recipe("foo", "https://x/foo.deb"))


def test_source_package_is_not_prebuilt():
    assert not prebuilt_declared(_recipe("foo-git", "https://x/foo.tar.gz"))
    assert not prebuilt_declared(None)


def test_declared_claims_includes_p009():
    assert P_PREBUILT in declared_claims(prebuilt=True)
    assert P_PREBUILT not in declared_claims()


def test_score_reports_p009_at_weight_zero():
    score, breakdown, _risk = calculate_score(
        [], {}, NoveltyContext(), prebuilt=True)
    entry = next(e for e in breakdown if e.rule_id == P_PREBUILT)
    assert entry.weight == 0
    assert score == 0


def test_m001_pairs_p009_with_h066_only_when_declared():
    triggered = [{"rule_id": "H066"}]
    assert claim_contradictions(triggered, claims={P_PREBUILT})
    assert not claim_contradictions(triggered, claims=set())
