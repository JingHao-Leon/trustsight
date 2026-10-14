"""- the calibration gates, enforced.

`rebaseline.py` records what the fire rates *are*; this script decides
whether they are *allowed*. Every gate here is one line of the plan's
list turned into a number and a comparison, so a rule that drifts into
noise, a weight-0 annotation that quietly starts scoring, or a detection
that stops detecting fails the build instead of being noticed a month later
in a drift issue.

Usage:
    python scripts/calibration_gates.py
    python scripts/calibration_gates.py --sample 4 --json gates.json

Exit code is 1 if any gate fails, 0 otherwise.  `--sample N` scans every
Nth benign diff, which the test suite uses to keep a full corpus replay out
of the default run; the CI job runs it whole.
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import trustsight.config as config_module
import trustsight.db as db_module
from trustsight.analysis import scan_diff
from trustsight.analysis.base import _GLOBAL_URL_KEY
from trustsight.analysis.pipeline import scored_source_urls
from trustsight.config import ensure_default_configs, load_config
from trustsight.novelty import normalize_url
from trustsight.rules import (
    load_rules,
    precompile_patterns,
    precompile_structural_patterns,
    resolve_generated_patterns,
)
from trustsight.sandbox.client import reset_after_fork
from trustsight.sandbox.git_client import reset_after_fork as reset_git_after_fork
# Bootstrap the import path before reaching the ``scripts.calibration`` package.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

import scripts.calibration._core as _calib_core

def run_gates(corpus: Path = _calib_core.FIXTURES / "benign-corpus",
              malicious_root: Path = _calib_core.FIXTURES / "malicious",
              sample: int = 1, jobs: int | None = None) -> list[Gate]:
    with shipped_config():
        benign = scan_corpus(corpus, sample=sample, jobs=jobs)
        malicious = (scan_malicious(malicious_root, jobs=jobs)
                     if malicious_root.exists() else [])
        gates = _evaluate(benign, malicious)
        warm_root = malicious_root / "warm"
        if warm_root.exists():
            gates.append(gate_d_series_warm(warm_root))
        # The published distribution can only be compared against a whole
        # corpus: a sample moves every percentile.  `_evaluate` stays the
        # ten plan gates the sampled test run checks; this one rides the CI
        # job, which replays the corpus whole.
        if sample == 1:
            gates.append(gate_published_figures(benign, malicious))
            gates.append(gate_x_series_rate_stability(benign))
        return gates

def _evaluate(benign: list[dict], malicious: list[dict]) -> list[Gate]:

    gates = [
        gate_benign_fire_rates(benign),
        gate_score_not_size(benign),
        gate_weight_zero_annotations(benign),
        gate_h035_position(benign),
        gate_stateful_rules_stay_out(benign),
        gate_ioc_exact_match(benign),
        gate_homograph_single_script(),
        gate_meta_escalation_below_cap(benign),
        gate_manifest_benign_corpus(),
    ]
    if malicious:
        gates.append(gate_separation(benign, malicious))
        gates.append(gate_malicious_recall(malicious))
        gates.append(gate_known_gaps_unchanged(malicious))
        gates.append(gate_s_series_fixture_pairs(benign, malicious))
        gates.append(gate_s_series_last_fired_coverage(benign, malicious))
    gates.append(gate_cluster_rate_below_members(benign))
    return gates

def main() -> int:
    parser = argparse.ArgumentParser(description="Run the calibration gates")
    parser.add_argument("--corpus", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--malicious", type=Path, default=FIXTURES / "malicious")
    parser.add_argument("--sample", type=int, default=1,
                        help="Scan every Nth benign diff (default: all)")
    parser.add_argument("--jobs", type=int, default=default_jobs(),
                        help="Analysis worker processes (default: min(8, CPUs))")
    parser.add_argument("--json", type=Path, help="Write the gate results here")
    args = parser.parse_args()

    if not args.corpus.exists():
        print(f"Corpus not found: {args.corpus}", file=sys.stderr)
        print("Reconstruct it with scripts/build_corpus.py --from-manifest",
              file=sys.stderr)
        return 2

    gates = run_gates(args.corpus, args.malicious, sample=args.sample,
                      jobs=args.jobs)

    width = max(len(g.name) for g in gates)
    for gate in gates:
        status = "PASS" if gate.passed else "FAIL"
        print(f"{status}  {gate.name:<{width}}  measured={gate.measured}")
        if gate.detail:
            print(f"        {gate.detail}")

    if args.json:
        args.json.write_text(
            json.dumps([g.as_dict() for g in gates], indent=2, default=str) + "\n"
        )

    failed = [g for g in gates if not g.passed]
    print(f"\n{len(gates) - len(failed)}/{len(gates)} gates passed")
    return 1 if failed else 0

from scripts.calibration._core import (
    CLASS_C_RULES,
    CLASS_D_RULES,
    CRITICAL_MIN_SCORE,
    FIXTURES,
    Gate,
    MANIFEST_CORPUS,
    MAX_BENIGN_FIRE_RATE,
    MAX_SCORE_SIZE_CORRELATION,
    MAX_X_RATE_DRIFT,
    ROOT,
    X_RULES,
    _GAP_PRIOR_RULES,
    _META_ESCALATORS,
    _NOT_RULES,
    _S_RULES,
    _WORKER_CONFIG,
    _WORKER_INCLUDE_LOCATION,
    _WORKER_RULES,
    _benign_plan,
    _benign_row,
    _diff_line_count,
    _fixture_failures,
    _gap_detected_by_another_rule,
    _init_worker,
    _is_attack_fixture,
    _malicious_row,
    _ordered_benign_packages,
    _precompile_patterns,
    _resolve_jobs,
    _scan_corpus_parallel,
    _scan_corpus_serial,
    _scan_malicious_task,
    _scan_package_task,
    default_jobs,
    pearson,
    percentile,
    scan_corpus,
    scan_malicious,
    shipped_config,
    warm_dependency_corpus,
)
from scripts.calibration._gates import (
    gate_benign_fire_rates,
    gate_cluster_rate_below_members,
    gate_d_series_warm,
    gate_h035_position,
    gate_homograph_single_script,
    gate_ioc_exact_match,
    gate_known_gaps_unchanged,
    gate_malicious_recall,
    gate_manifest_benign_corpus,
    gate_meta_escalation_below_cap,
    gate_published_figures,
    gate_s_series_fixture_pairs,
    gate_s_series_last_fired_coverage,
    gate_score_not_size,
    gate_separation,
    gate_stateful_rules_stay_out,
    gate_weight_zero_annotations,
    gate_x_series_rate_stability,
)

__all__ = ['CLASS_C_RULES', 'CLASS_D_RULES', 'CRITICAL_MIN_SCORE', 'Counter', 'FIXTURES', 'Gate', 'MANIFEST_CORPUS', 'MAX_BENIGN_FIRE_RATE', 'MAX_SCORE_SIZE_CORRELATION', 'MAX_X_RATE_DRIFT', 'Path', 'ProcessPoolExecutor', 'ROOT', 'X_RULES', '_GAP_PRIOR_RULES', '_GLOBAL_URL_KEY', '_META_ESCALATORS', '_NOT_RULES', '_S_RULES', '_WORKER_CONFIG', '_WORKER_INCLUDE_LOCATION', '_WORKER_RULES', '_benign_plan', '_benign_row', '_diff_line_count', '_evaluate', '_fixture_failures', '_gap_detected_by_another_rule', '_init_worker', '_is_attack_fixture', '_malicious_row', '_ordered_benign_packages', '_precompile_patterns', '_resolve_jobs', '_scan_corpus_parallel', '_scan_corpus_serial', '_scan_malicious_task', '_scan_package_task', 'argparse', 'config_module', 'contextmanager', 'db_module', 'default_jobs', 'defaultdict', 'ensure_default_configs', 'gate_benign_fire_rates', 'gate_cluster_rate_below_members', 'gate_d_series_warm', 'gate_h035_position', 'gate_homograph_single_script', 'gate_ioc_exact_match', 'gate_known_gaps_unchanged', 'gate_malicious_recall', 'gate_manifest_benign_corpus', 'gate_meta_escalation_below_cap', 'gate_published_figures', 'gate_s_series_fixture_pairs', 'gate_s_series_last_fired_coverage', 'gate_score_not_size', 'gate_separation', 'gate_stateful_rules_stay_out', 'gate_weight_zero_annotations', 'gate_x_series_rate_stability', 'json', 'load_config', 'load_rules', 'main', 'math', 'multiprocessing', 'normalize_url', 'os', 'pearson', 'percentile', 'precompile_patterns', 'precompile_structural_patterns', 'reset_after_fork', 'reset_git_after_fork', 'resolve_generated_patterns', 'run_gates', 'scan_corpus', 'scan_diff', 'scan_malicious', 'scored_source_urls', 'shipped_config', 'shutil', 'sys', 'tempfile', 'warm_dependency_corpus']


if __name__ == "__main__":
    sys.exit(main())
