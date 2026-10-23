#!/usr/bin/env python3
"""Build or import the artifact-manifest corpus.

The A-series reads a built package's file manifest, not a diff.  This corpus
gives every stratum a representative manifest plus negative controls, so the
artifact layer has the same shape coverage as the diff corpus.

Two input modes:

  * ``--write-fixtures`` regenerates the committed corpus from the reviewed
    definitions below.  These are small, explicit manifests: the A-series rule
    is about file paths, modes, links and declarations, not about the binary
    payload, so a reviewed manifest is a complete fixture.
  * ``--from-dir DIR`` imports manifests produced by a real build
    (``trustsight verify-build`` output or an equivalent JSON file).  Real
    builds are an out-of-tree, containerised operation; this script never
    executes package code itself.

Usage:
    python scripts/build_artifact_corpus.py --write-fixtures
    python scripts/build_artifact_corpus.py --from-dir /tmp/manifests
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "artifact-corpus"


def _file(path: str, mode: int = 0o644, **fields) -> dict:
    return {"path": path, "mode": mode, **fields}


FIXTURES: dict[str, dict] = {
    "data_fonts": {
        "stratum": "data_fonts",
        "description": "Negative control: a font package's manifest must trip no A rule.",
        "manifest": [
            _file("/usr/share/fonts/TTF/Demo-Regular.ttf"),
            _file("/usr/share/fonts/TTF/Demo-Bold.ttf"),
            _file("/usr/share/licenses/demo-font/LICENSE"),
            _file("/usr/share/fonts/TTF/"),
        ],
        "declared": {"depends": []},
        "expected": [],
    },
    "persist_surface": {
        "stratum": "persist_surface",
        "description": "A service is installed but the recipe declares no units.",
        "manifest": [
            _file("/usr/bin/demo", 0o755),
            _file("/usr/lib/systemd/system/demo.service"),
        ],
        "declared": {"depends": [], "units": []},
        "expected": ["A002"],
    },
    "signed_sources": {
        "stratum": "signed_sources",
        "description": "A normal signed-source package installs an unusual executable.",
        "manifest": [
            _file("/opt/demo/bin/demo", 0o755),
            _file("/usr/share/licenses/demo/LICENSE"),
        ],
        "declared": {"depends": []},
        "expected": ["A005"],
    },
    "multi_client_fetch": {
        "stratum": "multi_client_fetch",
        "description": "A helper links zlib without declaring it in depends.",
        "manifest": [
            _file("/usr/bin/demo", 0o755),
            _file("/usr/lib/demo/libhelper.so", links=["libz.so.1"]),
        ],
        "declared": {"depends": ["glibc"]},
        "expected": ["A003"],
    },
    "maintainer_churn": {
        "stratum": "maintainer_churn",
        "description": "An ordinary ELF install; no artifact finding.",
        "manifest": [_file("/usr/bin/demo", 0o755)],
        "declared": {"depends": []},
        "expected": [],
    },
    "dependency_heavy": {
        "stratum": "dependency_heavy",
        "description": "A polkit rule is installed by a package that does not explain it.",
        "manifest": [
            _file("/usr/bin/demo", 0o755),
            _file("/etc/polkit-1/rules.d/50-demo.rules"),
        ],
        "declared": {"depends": []},
        "expected": ["A007"],
    },
    "vcs_other": {
        "stratum": "vcs_other",
        "description": "An ordinary ELF install from a non-git VCS; no artifact finding.",
        "manifest": [_file("/usr/bin/demo", 0o755)],
        "declared": {"depends": []},
        "expected": [],
    },
    "appimage_repack": {
        "stratum": "appimage_repack",
        "description": "An AppImage is unpacked and installed executable outside /usr/bin.",
        "manifest": [_file("/opt/demo/demo.AppImage", 0o755)],
        "declared": {"depends": []},
        "expected": ["A005"],
    },
    "lang_deep": {
        "stratum": "lang_deep",
        "description": "A package ships an eBPF object.",
        "manifest": [
            _file("/usr/bin/demo", 0o755),
            _file("/usr/lib/demo/filter.bpf.o"),
        ],
        "declared": {"depends": []},
        "expected": ["A008"],
    },
}


def write_fixtures(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    expected = {}
    for name, doc in FIXTURES.items():
        (directory / f"{name}.json").write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n")
        expected[f"{name}.json"] = {
            "stratum": doc["stratum"],
            "expected": doc["expected"],
            "description": doc["description"],
        }
    (directory / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n")
    print(f"artifact corpus: {len(FIXTURES)} manifests -> {directory}")
    return 0


def import_manifests(source: Path, directory: Path) -> int:
    """Import reviewed manifest JSON files from a real build lane."""
    directory.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(source.glob("*.json")):
        doc = json.loads(path.read_text())
        if "manifest" not in doc:
            continue
        doc.setdefault("stratum", path.stem)
        doc.setdefault("declared", {})
        doc.setdefault("expected", [])
        (directory / path.name).write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n")
        count += 1
    print(f"artifact corpus: imported {count} manifest(s) into {directory}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Artifact-manifest corpus")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--write-fixtures", action="store_true")
    parser.add_argument("--from-dir", type=Path)
    args = parser.parse_args()
    if args.from_dir:
        return import_manifests(args.from_dir, args.out)
    if args.write_fixtures:
        return write_fixtures(args.out)
    parser.error("pass --write-fixtures or --from-dir")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
