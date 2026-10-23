#!/usr/bin/env python3
"""Measure whether the AUR's shape distribution has drifted from the corpus.

Re-runs the metadata-stage selection predicates against current AUR metadata
and compares the candidate share per stratum with the committed lock.  This
turns "the corpus aged" into a measured trigger: a stratum whose live share
moves more than the configured tolerance gets an issue, so a rebase is a
deliberate response rather than a monthly surprise.

Usage:
    python scripts/corpus_shape_drift.py [--json drift.json] [--tolerance 0.10]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_corpus  # noqa: E402
import corpus_select  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--strata", type=Path, default=ROOT / "scripts" / "strata.toml")
    parser.add_argument("--tolerance", type=float, default=0.10)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--refresh-meta", action="store_true")
    args = parser.parse_args()

    lock = json.loads(args.manifest.read_text())
    locked = Counter(e["stratum"] for e in lock.get("entries", []))
    meta = build_corpus.fetch_meta(force=args.refresh_meta)
    live = {}
    all_names = {e["pkg"] for e in lock.get("entries", [])}
    for stratum in corpus_select.EXISTING + corpus_select.NEW:
        live[stratum] = sum(
            1 for pkg in meta
            if corpus_select.metadata_match(pkg, stratum))
    live_total = max(1, len(meta))
    locked_total = max(1, sum(locked.values()))

    rows = {}
    drifted = {}
    for stratum in corpus_select.EXISTING + corpus_select.NEW:
        old = locked.get(stratum, 0) / locked_total
        new = live.get(stratum, 0) / live_total
        delta = new - old
        rows[stratum] = {
            "locked_entries": locked.get(stratum, 0),
            "locked_share": round(old, 5),
            "live_candidates": live.get(stratum, 0),
            "live_share": round(new, 5),
            "delta": round(delta, 5),
        }
        if old > 0 and abs(delta) / old > args.tolerance:
            drifted[stratum] = rows[stratum]

    report = {
        "locked_packages": sum(locked.values()),
        "live_packages": len(meta),
        "known_packages": len(all_names),
        "tolerance": args.tolerance,
        "strata": rows,
        "drifted": drifted,
    }
    text = json.dumps(report, indent=2) + "\n"
    if args.json:
        args.json.write_text(text)
    print(text, end="")
    print(f"shape drift: {len(drifted)} stratum/strata beyond {args.tolerance:.0%}",
          file=sys.stderr)
    return 1 if drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
