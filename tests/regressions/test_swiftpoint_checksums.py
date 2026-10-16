"""Swiftpoint watcher alert 2026-10-16/152534: paired local-source removal."""

from difflib import unified_diff

import pytest

from trustsight.differ import detect_checksum_changes
from trustsight.analysis.crossfire import X015_RE

from .helpers import _ids, _x


def _transition(remove_source=True, wrong_hash=False):
    old = (
        'pkgname=swiftpoint-x1-control-panel\n'
        'source=("https://example.test/p.tar.xz"\n'
        '        "https://example.test/icon.png"\n'
        '        "panel.desktop"\n'
        '        "panel.service")\n'
        'install=panel.install\n'
        "sha256sums=(\n" +
        "".join(f"  '{c * 64}'\n" for c in "abcd") + ")\n"
    )
    new = old
    if remove_source:
        new = new.replace('        "panel.desktop"\n        "panel.service")',
                          '        "panel.desktop")')
    new = new.replace(f"  '{('c' if wrong_hash else 'd') * 64}'\n", "")
    diff = "".join(unified_diff(old.splitlines(True), new.splitlines(True),
                                fromfile="a/PKGBUILD", tofile="b/PKGBUILD", n=20))
    return diff, new


def test_local_source_and_its_checksum_removed_together():
    diff, current = _transition()
    assert detect_checksum_changes(diff) == "checksum_added_or_changed"
    assert "C004" not in _ids(diff, current_text=current)


@pytest.mark.parametrize("remove_source,wrong_hash", [(False, False), (True, True)])
def test_a_count_match_does_not_excuse_losing_a_retained_sources_hash(remove_source, wrong_hash):
    diff, current = _transition(remove_source, wrong_hash)
    assert detect_checksum_changes(diff) == "checksum_entry_removed"
    assert "C004" in _ids(diff, current_text=current)


def test_partial_source_array_cannot_prove_a_paired_removal():
    diff, _ = _transition()
    diff = diff.replace(' source=("https://example.test/p.tar.xz"\n', "")
    assert detect_checksum_changes(diff) == "checksum_entry_removed"


def test_paired_removal_does_not_hide_a_new_skip():
    diff, _ = _transition()
    diff = diff.replace(f"   '{'a' * 64}'\n",
                        f"-  '{'a' * 64}'\n+  'SKIP'\n")
    assert detect_checksum_changes(diff) == "changed_from_sha256_to_skip"


@pytest.mark.parametrize("command", [
    "udevadm control --reload-rules",
    "udevadm control --reload",
])
def test_udev_reload_is_not_deferred_execution(command):
    assert X015_RE.search(command) is None
    assert "X015" not in _x(["post_install() {", f"  {command}", "}"])


@pytest.mark.parametrize("command", [
    'echo \'RUN+="/opt/payload"\' > "$pkgdir/usr/lib/udev/rules.d/evil.rules"',
    "systemd-run --on-active=60 /opt/payload",
    "echo /opt/payload | batch",
    "systemctl start evil.service",
])
def test_real_deferred_work_is_still_detected(command):
    assert X015_RE.search(command)
    assert "X015" in _x([f"  {command}"])
