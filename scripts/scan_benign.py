#!/usr/bin/env python3
"""Parallel benign-corpus scan for rule work.

Runs the same whole-corpus scan the calibration gates use - the shipped
config, the package-level process pool - and prints the published-figures
statistics plus per-rule firing counts.  One pass answers every rule
question, so checking a change does not mean re-scanning the corpus once per
rule.  Read-only: it asserts nothing and writes nothing.

Usage:
    uv run python scripts/scan_benign.py
    uv run python scripts/scan_benign.py --jobs 4
    uv run python scripts/scan_benign.py --rule H083 --rule X033
    uv run python scripts/scan_benign.py --top 30
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import calibration_gates as cg  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path,
                        default=cg.FIXTURES / "benign-corpus")
    parser.add_argument("--jobs", type=int, default=None,
                        help="worker processes (default: every core)")
    parser.add_argument("--sample", type=int, default=1)
    parser.add_argument("--rule", action="append", default=[],
                        help="report every firing of this rule (repeatable)")
    parser.add_argument("--top", type=int, default=20,
                        help="with no --rule, how many rules to list")
    args = parser.parse_args()

    with cg.shipped_config():
        rows = cg.scan_corpus(args.corpus, sample=args.sample, jobs=args.jobs)

    from trustsight.scoring import FLAG_THRESHOLD

    n = len(rows)
    if not n:
        print("no diffs scanned", file=sys.stderr)
        return 1
    scores = sorted(r["score"] for r in rows)
    fired = [r for r in rows
             if any(e["severity"] != "INFO" for e in r["entries"])]
    print(
        f"diffs={n} "
        f"zero-rate={sum(1 for s in scores if s == 0) / n * 100:.1f}% "
        f"p95={cg.percentile(scores, 0.95)} "
        f"flag>{FLAG_THRESHOLD}={sum(1 for s in scores if s > FLAG_THRESHOLD) / n * 100:.1f}% "
        f"trigger={len(fired) / n * 100:.1f}%"
    )

    if args.rule:
        for rule_id in args.rule:
            hits = [(r["path"].name, r["score"]) for r in rows
                    if any(e["rule_id"] == rule_id for e in r["entries"])]
            print(f"\n{rule_id}: {len(hits)} firing(s)")
            for name, score in hits:
                print(f"  {score:>3}  {name}")
    else:
        counts = Counter(e["rule_id"] for r in rows for e in r["entries"])
        print("\ntop rules by firing count:")
        for rule_id, count in counts.most_common(args.top):
            print(f"  {count:>5}  {rule_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
