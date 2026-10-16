"""Cargo prefetch is not BSD fetch followed by an unrelated project script."""

import pytest

from trustsight.analysis.buildfetch import registry_resolutions
from trustsight.analysis.edges import build_context, run_edge_instances
from trustsight.analysis.structural._hygiene import capability_in_diff
from trustsight.rules import ScopeResolver, _classify_line_context


def _diff(*lines, header=""):
    return ("--- a/PKGBUILD\n+++ b/PKGBUILD\n"
            f"@@ -10,0 +10,{len(lines)} @@ {header}\n"
            + "".join("+" + line + "\n" for line in lines))


def _ids(diff):
    findings = []
    run_edge_instances(build_context(diff, {}),
                       lambda rule, *args, **kwargs: findings.append(rule))
    return set(findings)


@pytest.mark.parametrize("flags", ["--locked", "--frozen", "--offline", ""])
def test_cargo_fetch_is_not_an_unattributed_payload(flags):
    diff = _diff("prepare() {", f"  cargo fetch {flags}", "}",
                 "build() {", "  cargo build --frozen --release",
                 '  python scripts/collect-licenses.py "$srcdir/licenses"', "}")
    assert not (_ids(diff) & {"H077", "H082"})
    assert capability_in_diff(_diff("prepare() {", f"  cargo fetch {flags}", "}")) is None


@pytest.mark.parametrize("fetch", [
    "fetch -o x.sh https://example.org/x.sh",
    'fetch -o x.sh "$url"',
    'command fetch -o x.sh "$url"',
    'curl -o x.sh "$url"',
    'git fetch origin',
])
def test_real_fetch_execute_still_detected(fetch):
    assert "H082" in _ids(_diff("prepare() {", "  " + fetch, "}",
                                "build() {", "  bash x.sh", "}"))


def test_hunk_function_scope_and_removed_closure():
    diff = _diff("  cargo fetch --locked", "}", header="prepare() {")
    lines = diff.splitlines()
    index = next(i for i, line in enumerate(lines) if "cargo fetch" in line)
    assert ScopeResolver(lines).direct(index) == "prepare"
    assert _classify_line_context(lines)[index] == "function_body"
    assert "H077" not in _ids(diff)
    assert "H077" in _ids(diff + "@@ -30,0 +30,1 @@\n+curl https://example.org/x\n")
    changed = diff.replace("+  cargo", "-}\n+  cargo")
    assert "H077" not in _ids(changed)


@pytest.mark.parametrize("command, expected", [
    ("cargo build --frozen", False),
    ("cargo fetch --frozen", False),
    ("cargo build --offline", False),
    ("cargo fetch --locked", True),
    ("cargo build", True),
    ("cargo build --frozen; npm install payload", True),
    ("cargo build --frozen; cargo fetch --locked", True),
    ("npm install --frozen", True),
])
def test_registry_gap_respects_cargo_network_constraints(command, expected):
    assert bool(registry_resolutions(_diff("prepare() {", "  " + command, "}"))) is expected


@pytest.mark.parametrize("command, expected", [
    ("cargo fetch --locked", True),
    ("cargo fetch --frozen", False),
    ("cargo fetch --offline", False),
    ("cargo fetch --frozen; curl https://example.org/x", True),
    ('cargo fetch --frozen --target "$(curl https://example.org/target)"', True),
])
def test_parse_time_cargo_requires_possible_network(command, expected):
    assert ("H077" in _ids(_diff(command))) is expected


@pytest.mark.parametrize("flag, expected", [("--frozen", False), ("--locked", True)])
def test_parse_time_cargo_helper_requires_possible_network(flag, expected):
    diff = _diff(f"_fetch() {{ cargo fetch {flag}; }}", "_version=$(_fetch)")
    assert ("H077" in _ids(diff)) is expected


@pytest.mark.parametrize("command, online", [
    ('cargo fetch --frozen --target "$(cargo fetch --locked >/dev/null; '
     'printf x86_64-unknown-linux-gnu)"', True),
    ("cargo fetch --config 'env.NOTE=\" --frozen \"'", True),
    ("cargo fetch --config 'env.NOTE=\" --offline \"'", True),
    ("cargo fetch --config '--frozen'", True),
    ("cargo fetch -- --frozen", True),
    ("cargo fetch --unknown --frozen", True),
    ("cargo fetch --config 'env.NOTE=\" --frozen \"' --offline", False),
    ("cargo fetch --target x86_64-unknown-linux-gnu --frozen", False),
    ("cargo fetch --config 'env.NOTE=\"x\"' --frozen", False),
    ('cargo fetch --offline --target "`cargo fetch --locked`"', True),
    ('cargo fetch --frozen --target "$(cargo fetch --frozen)"', True),
])
def test_network_exemptions_require_proven_invocation_options(command, online):
    from trustsight.analysis.network import _has_parse_time_fetch, _parse_time_fetch_patterns

    assert _has_parse_time_fetch(command, _parse_time_fetch_patterns()) is online
    assert ("H077" in _ids(_diff(command))) is online
    assert bool(registry_resolutions(_diff("prepare() {", "  " + command, "}"))) is online


def test_full_aur_suffix_free_hunks_preserve_build_scope():
    from trustsight.full_aur.analyze import _make_diff_text

    old = "build() {\n" + "\n".join(f"  echo line{i}" for i in range(30)) + "\n}\n"
    new = old.replace("echo line1\n", "echo changed\n").replace(
        "echo line25\n", "cargo fetch --locked\n"
    )
    diff = _make_diff_text(old, new)
    assert diff.count("@@ -") == 2
    assert all(line.endswith("@@") for line in diff.splitlines() if line.startswith("@@"))
    lines = diff.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("+  cargo"))
    assert ScopeResolver(lines).direct(index) == "build"
    assert _classify_line_context(lines)[index] == "function_body"
    assert registry_resolutions(diff) == [("build", "cargo fetch --locked")]
    assert "H077" not in _ids(diff)
    fetch_diff = diff.replace("cargo fetch --locked", "curl https://example.org/payload")
    assert "H016" in _ids(fetch_diff)

    # An explicit header still replaces a carried scope.
    lines += ["@@ -60,0 +60,2 @@ prepare() {", "+  cargo fetch --locked", "+}"]
    assert ScopeResolver(lines).direct(len(lines) - 2) == "prepare"
