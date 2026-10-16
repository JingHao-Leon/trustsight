"""Local SKIPs must not excuse unchecked downloads in another slot."""

import pytest

from trustsight.analysis.structural import _structural_findings
from trustsight.differ import extract_urls_from_diff


@pytest.mark.parametrize("sources,sums,severity", [
    ("source=('fix.patch')", "sha256sums=('SKIP')", "INFO"),
    ("source_x86_64=('fix.patch')", "b2sums_x86_64=('SKIP')", "INFO"),
    ("source_x86_64=('fix.patch')", "b2sums_x86_64=(\n 'SKIP'\n)", "INFO"),
    ("source=('https://example.org/a' 'fix.patch')", "sha256sums=('abc' 'SKIP')", "INFO"),
    ("source=('fix.patch' 'https://example.org/a')", "sha256sums=('abc' 'SKIP')", "HIGH"),
    ("source=('fix.patch' 'https://example.org/a')", "sha256sums=('SKIP' 'SKIP')", "HIGH"),
    ("source=('git+https://example.org/a' 'https://example.org/b')", "sha256sums=('SKIP' 'SKIP')", "HIGH"),
    ("source=('fix.patch')", "sha256sums_x86_64=('SKIP')", "HIGH"),
    ("source=('fix.patch')", "sha256sums=('SKIP' 'SKIP')", "HIGH"),
    ("source=('${unknown}')", "sha256sums=('SKIP')", "HIGH"),
    ("source=('file::https://example.org/a')", "sha256sums=('SKIP')", "HIGH"),
    ("source=('magnet:abc')", "sha256sums=('SKIP')", "HIGH"),
    ("source=('fix.patch')\nsource_aarch64=('https://example.org/a')",
     "sha256sums=('SKIP')\nsha256sums_aarch64=('SKIP')", "HIGH"),
])
@pytest.mark.parametrize("full_text", [True, False])
def test_h001_local_skip_pairing(sources, sums, severity, full_text):
    current = sources + "\n" + sums + "\n"
    diff = f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -0,0 +1,{len(current.splitlines())} @@\n"
    diff += "".join("+" + line + "\n" for line in current.splitlines())
    findings = _structural_findings(
        diff, extract_urls_from_diff(diff),
        current_text=current if full_text else None,
    )
    finding = next(f for f in findings if f["rule_id"] == "H001")
    assert finding["severity"] == severity


def test_local_source_outside_hunk_requires_head_recipe():
    diff = "-sha256sums=('abc')\n+sha256sums=('SKIP')\n"
    for current, severity in [(None, "HIGH"), (
        "source=('fix.patch')\nsha256sums=('SKIP')\n", "INFO",
    )]:
        findings = _structural_findings(
            diff, extract_urls_from_diff(diff), current_text=current,
        )
        assert next(f for f in findings if f["rule_id"] == "H001")["severity"] == severity
