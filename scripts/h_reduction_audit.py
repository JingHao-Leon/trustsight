"""Addendum 3 Phase 5, Step 1: the H-series overlap and zero-fire audit.

Reads the locked benign corpus and the labelled malicious fixtures through the
calibration scanner and computes, for every rule ID:

- its benign and malicious firing counts, and
- for each audited candidate pair, the co-fire ratio
  ``|A & B| / min(|A|, |B|)``.

Decision rule (published, not applied here): a pair co-firing at or above the
epsilon (default 0.95 of the rarer rule's firings) *may* merge, with the
higher-severity ID surviving.  This script measures; it never retires an ID.
The output is the evidence a human adjudicates in the changelog.

Usage:
    uv run python scripts/h_reduction_audit.py [--sample N] [--json out.json]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import calibration_gates as gates  # noqa: E402

#: The audited candidate pairs from Addendum 3 Phase 5 Step 1.
CANDIDATES = (
    ("H026", "H044"), ("H045", "H073"), ("H022", "H060"),
    ("H074", "H088"), ("H053", "H059"), ("H016", "H042"),
    ("H072", "H082"), ("H012", "H013"), ("H020", "H021"),
)

#: Rules that are load-bearing composition/meta and never a merger target.
_META = frozenset({"H027", "H036", "H043", "H055", "H098"})


def cofire_row(left: str, right: str,
               benign_fired: dict[str, set[int]],
               mal_sets: dict[str, set[int]],
               mal_counts: dict[str, int],
               epsilon: float) -> dict:
    """The co-fire measurement for one candidate pair (pure, testable)."""
    both = (
        len(benign_fired.get(left, set()) & benign_fired.get(right, set()))
        + len(mal_sets.get(left, set()) & mal_sets.get(right, set()))
    )
    a_hits = len(benign_fired.get(left, ())) + mal_counts.get(left, 0)
    b_hits = len(benign_fired.get(right, ())) + mal_counts.get(right, 0)
    rarer = min(a_hits, b_hits)
    ratio = (both / rarer) if rarer else 0.0
    return {
        "pair": [left, right],
        "a_hits": a_hits, "b_hits": b_hits, "both": both,
        "ratio_of_rarer": round(ratio, 4),
        "meets_epsilon": ratio >= epsilon,
        "measured": bool(rarer),
    }


def _fired_sets() -> dict[str, set[int]]:
    """Rule id -> the set of corpus-diff indices (benign) it fired on."""
    benign = gates.scan_corpus(
        gates.FIXTURES / "benign-corpus", sample=1, jobs=gates.default_jobs())
    fired: dict[str, set[int]] = {}
    for index, row in enumerate(benign):
        for entry in row["entries"]:
            fired.setdefault(entry["rule_id"], set()).add(index)
    return fired


def _malicious_sets() -> tuple[dict[str, int], dict[str, set[int]]]:
    """Counts per rule and rule -> the malicious-fixture indices it fired on."""
    malicious = gates.scan_malicious(
        gates.FIXTURES / "malicious", jobs=gates.default_jobs())
    counts: dict[str, int] = {}
    sets: dict[str, set[int]] = {}
    for index, row in enumerate(malicious):
        for rule_id in row["fired"]:
            counts[rule_id] = counts.get(rule_id, 0) + 1
            sets.setdefault(rule_id, set()).add(index)
    return counts, sets


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="H-series reduction audit")
    parser.add_argument("--sample", type=int, default=1)
    parser.add_argument("--epsilon", type=float, default=0.95)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)

    fired = _fired_sets()
    mal_counts, mal_sets = _malicious_sets()

    from trustsight.categories import RULE_CATEGORIES

    all_h = sorted(rid for rid in RULE_CATEGORIES if rid.startswith("H"))
    per_rule = {
        rule_id: {
            "benign": len(fired.get(rule_id, ())),
            "malicious": mal_counts.get(rule_id, 0),
        }
        for rule_id in all_h
    }

    cofire = [
        cofire_row(left, right, fired, mal_sets, mal_counts, args.epsilon)
        for left, right in CANDIDATES
    ]

    zero_fire = [
        rule_id for rule_id in all_h
        if rule_id not in _META
        and per_rule[rule_id]["benign"] == 0
        and per_rule[rule_id]["malicious"] == 0
    ]

    report = {
        "epsilon": args.epsilon,
        "candidates": cofire,
        "zero_fire": zero_fire,
        "live_h": len(all_h),
        "per_rule": per_rule,
    }
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"wrote {args.json}")

    print("co-fire candidates (ratio of the rarer rule):")
    for row in cofire:
        flag = "MERGE-CANDIDATE" if row["meets_epsilon"] else "distinct"
        print(f"  {row['pair'][0]}/{row['pair'][1]}: "
              f"{row['both']}/{min(row['a_hits'], row['b_hits'])} "
              f"= {row['ratio_of_rarer']}  [{flag}]")
    print(f"zero-fire H rules ({len(zero_fire)}): {', '.join(zero_fire)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
