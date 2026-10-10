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
sys.path.insert(0, str(ROOT / "tests" / "harness"))

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
               epsilon: float,
               history_fired: dict[str, set[int]] | None = None) -> dict:
    """The co-fire measurement for one candidate pair (pure, testable).

    Every dimension is "the inputs a rule fired on": benign diffs, malicious
    fixtures, and (Addendum 3) the history cycles.  A pair co-fires when both
    sides fire on the *same* input in any dimension.
    """
    history_fired = history_fired or {}
    both = (
        len(benign_fired.get(left, set()) & benign_fired.get(right, set()))
        + len(mal_sets.get(left, set()) & mal_sets.get(right, set()))
        + len(history_fired.get(left, set()) & history_fired.get(right, set()))
    )
    a_hits = (len(benign_fired.get(left, ())) + mal_counts.get(left, 0)
              + len(history_fired.get(left, ())))
    b_hits = (len(benign_fired.get(right, ())) + mal_counts.get(right, 0)
              + len(history_fired.get(right, ())))
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

    # Addendum 3: the history cycles exercise the observation-history rules
    # the stateless corpus cannot, so they join the co-fire measurement.
    from history_replay import replay as _history_replay

    history_rows = _history_replay()
    history_fired: dict[str, set[int]] = {}
    for cycle_index, row in enumerate(history_rows):
        for rule_id in row["fired"]:
            history_fired.setdefault(rule_id, set()).add(cycle_index)

    from trustsight.categories import RULE_CATEGORIES
    from trustsight.rule_id_history import ANCHOR_RULE_IDS

    all_h = sorted(rid for rid in RULE_CATEGORIES if rid.startswith("H"))
    per_rule = {
        rule_id: {
            "benign": len(fired.get(rule_id, ())),
            "malicious": mal_counts.get(rule_id, 0),
            "history": len(history_fired.get(rule_id, ())),
        }
        for rule_id in all_h
    }

    cofire = []
    for left, right in CANDIDATES:
        row = cofire_row(left, right, fired, mal_sets, mal_counts,
                         args.epsilon, history_fired=history_fired)
        # The epsilon is necessary but not sufficient: a merge also needs the
        # two rules' evidence to describe the same shape.  The categories are
        # reported so the adjudication has both inputs.
        row["categories"] = [
            RULE_CATEGORIES.get(left, "").value if left in RULE_CATEGORIES
            else "",
            RULE_CATEGORIES.get(right, "").value if right in RULE_CATEGORIES
            else "",
        ]
        row["same_category"] = row["categories"][0] == row["categories"][1]
        cofire.append(row)

    zero_fire = [
        rule_id for rule_id in all_h
        if rule_id not in _META and rule_id not in ANCHOR_RULE_IDS
        and per_rule[rule_id]["benign"] == 0
        and per_rule[rule_id]["malicious"] == 0
        and per_rule[rule_id]["history"] == 0
    ]

    report = {
        "epsilon": args.epsilon,
        "history_cycles": len(history_rows),
        "candidates": cofire,
        "zero_fire": zero_fire,
        "live_h": len([rid for rid in all_h if rid not in ANCHOR_RULE_IDS]),
        "anchors": sorted(ANCHOR_RULE_IDS),
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
