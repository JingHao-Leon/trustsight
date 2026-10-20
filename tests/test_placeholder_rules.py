"""H104: placeholder package detection (2-of-3 signals)."""

from __future__ import annotations

from trustsight.analysis.placeholder import (
    is_placeholder_recipe,
    placeholder_finding,
)

PLACEHOLDER = """\
pkgname=name-reservation
pkgver=0.0.0
pkgrel=1
arch=(any)
source=()
sha256sums=()
package() {
  echo "reserved"
}
"""

REAL = """\
pkgname=realproject
pkgver=1.2.3
pkgrel=1
arch=(any)
source=("https://example.org/realproject-1.2.3.tar.gz")
sha256sums=("abc123")
package() {
  install -Dm755 "$srcdir/realproject" "$pkgdir/usr/bin/realproject"
}
"""


def test_placeholder_fires_on_two_of_three():
    assert is_placeholder_recipe(PLACEHOLDER)[0]


def test_real_package_does_not_fire():
    assert is_placeholder_recipe(REAL) == (False, None)


def test_single_signal_is_not_enough():
    only_version = REAL.replace("pkgver=1.2.3", "pkgver=0.0.0")
    assert not is_placeholder_recipe(only_version)[0]


def test_finding_shape():
    finding = placeholder_finding(PLACEHOLDER)
    assert finding is not None
    assert finding["rule_id"] == "H104"
    assert finding["severity"] == "INFO"
    assert finding["weight_override"] == 0
    assert "claims 'name-reservation'" in finding["match"]


def test_no_placeholder_returns_none():
    assert placeholder_finding(REAL) is None
    assert placeholder_finding(None) is None
