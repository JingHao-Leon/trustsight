"""Extracted from calibration_gates.py: _core."""

import json
import math
import multiprocessing
import os
import shutil
import tempfile
from collections import defaultdict
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

__all__ = ['CLASS_C_RULES', 'CLASS_D_RULES', 'CRITICAL_MIN_SCORE', 'FIXTURES', 'Gate', 'MANIFEST_CORPUS', 'MAX_BENIGN_FIRE_RATE', 'MAX_SCORE_SIZE_CORRELATION', 'MAX_X_RATE_DRIFT', 'ROOT', 'X_RULES', '_GAP_PRIOR_RULES', '_META_ESCALATORS', '_NOT_RULES', '_S_RULES', '_WORKER_CONFIG', '_WORKER_INCLUDE_LOCATION', '_WORKER_RULES', '_benign_plan', '_benign_row', '_diff_line_count', '_fixture_failures', '_gap_detected_by_another_rule', '_init_worker', '_is_attack_fixture', '_malicious_row', '_ordered_benign_packages', '_precompile_patterns', '_resolve_jobs', '_scan_corpus_parallel', '_scan_corpus_serial', '_scan_malicious_task', '_scan_package_task', '_scan_task', '_shard_tasks', 'default_jobs', 'pearson', 'percentile', 'scan_corpus', 'scan_corpus_tasks', 'scan_malicious', 'shipped_config', 'warm_dependency_corpus']

ROOT = Path(__file__).resolve().parent.parent.parent

FIXTURES = ROOT / "tests" / "fixtures"

MANIFEST_CORPUS = FIXTURES / "manifest-corpus"

_NOT_RULES = frozenset({
    "SOURCE_BUCKET", "NOVELTY", "VERIFICATION", "PINNING", "COVERAGE",
}) | frozenset(f"P{n:03d}" for n in range(1, 100))

MAX_BENIGN_FIRE_RATE = 0.30

MAX_SCORE_SIZE_CORRELATION = 0.30

CRITICAL_MIN_SCORE = 40

CLASS_C_RULES = frozenset({"H037", "H047", "H048", "H049", "H050", "H051", "H054"})

CLASS_D_RULES = frozenset({
    "H044", "H045", "H046", "H052", "H053", "H055", "H057", "H058", "H059",
    "H060", "H061", "H073", "H074",
    # H086 needs a recorded prior AUR orphan observation and H088 composes
    # it, so both are stateful and must be silent on the stateless path.
    # H087 is deliberately absent: it reads the diff alone, so it has a real
    # benign fire rate (11.5% on the locked corpus) and belongs to the
    # fire-rate gate rather than this one.
    "H086", "H088",
})

@contextmanager
def shipped_config():
    """Run the gates against the *shipped* config, never the machine's.

    ``rules.toml`` and friends are written once, at install time, and are
    never rewritten - so a developer box carries whatever the defaults were
    on the day it was first run.  Measuring against that file makes the
    numbers unreproducible and can hide a rule that has since been removed
    from the shipped set (or resurrect one that has).  The database is
    isolated for the same reason: novelty and maturity must start cold.

    The host's pacman answer is host state too: with a sync database
    present, ``official_package_names`` makes ``is_established_package``
    fire D004/H064 on benign provides-transitions that a machine without
    pacman (CI, a container) never reports - the benign flag rate measured
    7.9% with pacman and 7.8% without.  The frozen empty answer is the
    cold machine every environment can reproduce.
    """
    from trustsight.db import _dependencies as db_deps

    tmp = Path(tempfile.mkdtemp(prefix="trustsight-gates-"))
    saved_config, saved_data = config_module.CONFIG_DIR, db_module.DATA_DIR
    saved_official = db_deps._official_names
    config_module.CONFIG_DIR = tmp / "config"
    db_module.DATA_DIR = tmp / "data"
    db_module.DATA_DIR.mkdir(parents=True, exist_ok=True)
    # An empty set, not None: None means "never asked" and would re-query
    # pacman; the empty answer is what a machine without pacman gives.
    db_deps._official_names = frozenset()
    config_module._toml_cache.clear()
    try:
        ensure_default_configs()
        yield tmp
    finally:
        config_module.CONFIG_DIR = saved_config
        db_module.DATA_DIR = saved_data
        db_deps._official_names = saved_official
        config_module._toml_cache.clear()
        shutil.rmtree(tmp, ignore_errors=True)

@contextmanager
def warm_dependency_corpus():
    """The shipped config plus the committed dependency corpus.

    D001/D002 answer from ``dependency_names``, and the main gates run cold
    on purpose: an unseeded install must not make every dependency look
    novel.  This context is the warm half of that pair, seeding a small
    committed corpus so the corpus-dependent rules can be gated without
    moving the cold corpus figures.
    """
    with shipped_config() as tmp:
        from trustsight.db import init_db, record_dependency_names

        init_db()
        names = json.loads(
            (FIXTURES / "dependency-corpus.json").read_text()
        )["names"]
        # Ten observations each, the same warm-up the seeded-DB unit tests
        # use: enough for the typosquat candidate ranking to include them.
        for _ in range(10):
            record_dependency_names(names)
        yield tmp

class Gate:
    """One gate: a measurement, a threshold, and how it failed."""

    def __init__(self, name: str, passed: bool, measured, threshold, detail: str = ""):
        self.name = name
        self.passed = passed
        self.measured = measured
        self.threshold = threshold
        self.detail = detail

    def as_dict(self) -> dict:
        return {
            "gate": self.name, "passed": self.passed,
            "measured": self.measured, "threshold": self.threshold,
            "detail": self.detail,
        }

def _diff_line_count(text: str) -> int:
    return sum(
        1 for line in text.splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    )

def default_jobs() -> int:
    """The worker count a CLI run uses unless told otherwise."""
    return max(1, min(8, os.cpu_count() or 1))

def _resolve_jobs(jobs: int | None) -> int:
    """One worker unless a caller asks for more.

    Direct library callers (the tests) stay serial; the CLIs pass
    :func:`default_jobs` so a corpus run uses the machine.
    """
    if jobs is None or int(jobs) <= 0:
        return 1
    return max(1, int(jobs))

def _benign_row(
    package: str, path: Path, text: str, fact, include_location: bool
) -> dict:
    entries = []
    for e in fact.score_breakdown:
        entry = {"rule_id": e.rule_id, "severity": e.severity,
                 "weight": e.weight, "params": e.params or {}}
        if include_location:
            entry["file"] = e.file
            entry["line"] = e.line
        entries.append(entry)
    return {
        "package": package,
        "path": path,
        "score": fact.final_score,
        "lines": _diff_line_count(text),
        "entries": entries,
    }

def _ordered_benign_packages(corpus: Path) -> dict[str, list[Path]]:
    by_pkg: dict[str, list[Path]] = defaultdict(list)
    for path in sorted(corpus.rglob("*.diff")):
        by_pkg[path.name.split("__")[0]].append(path)
    return by_pkg

def _scan_corpus_serial_legacy(
    corpus: Path, sample: int, config: dict, rules,
    include_location: bool,
) -> list[dict]:
    """The original single-process walk: no plan pass, shared novelty state.

    Kept for ``jobs=1`` callers (the sampled test suite) because it reads
    each diff once; the plan-based serial path reads them twice to
    precompute prefixes.  ``tests/test_parallel_corpus.py`` pins it to the
    plan-based result.
    """
    by_pkg = _ordered_benign_packages(corpus)
    seen_urls: dict[str, set[str]] = {}
    results: list[dict] = []
    index = 0
    for pkg in sorted(by_pkg):
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            text = path.read_text(errors="replace")
            fact = scan_diff(text, rules=rules, config=config,
                             package_name=pkg, seen_urls=seen_urls)
            results.append(_benign_row(pkg, path, text, fact, include_location))
    return results

def _scan_task(task, rules, config: dict,
               include_location: bool) -> list[dict]:
    """Scan one package task: its diffs stay serial, novelty in order."""
    package, paths, prefix = task
    pkg_seen: set[str] = set()
    global_seen = set(prefix)
    rows = []
    for path_str in paths:
        path = Path(path_str)
        text = path.read_text(errors="replace")
        fact = scan_diff(
            text, rules=rules, config=config, package_name=package,
            seen_urls={package: pkg_seen, _GLOBAL_URL_KEY: global_seen},
        )
        rows.append(_benign_row(package, path, text, fact, include_location))
    return rows

def _shard_tasks(plan, shard):
    """``(task_index, task)`` pairs for shard ``I/N``, or the whole plan.

    Indexing is the position in the plan (not the raw package walk), so
    every shard agrees on which tasks are its own.  The plan carries each
    package's precomputed novelty prefix, so a subset produces exactly the
    rows a whole run does.
    """
    if shard is None:
        return list(enumerate(plan))
    index, total = shard
    return [(i, task) for i, task in enumerate(plan) if i % total == index]

def _scan_corpus_serial(plan, shard, rules, config: dict,
                        include_location: bool) -> list[tuple[int, list[dict]]]:
    return [
        (index, _scan_task(task, rules, config, include_location))
        for index, task in _shard_tasks(plan, shard)
    ]

def _scan_package_task(task):
    return _scan_task(
        task, _WORKER_RULES, _WORKER_CONFIG, _WORKER_INCLUDE_LOCATION
    )

def _scan_corpus_parallel(
    plan, shard, workers: int, rules, config: dict, include_location: bool
) -> list[tuple[int, list[dict]]]:
    selected = _shard_tasks(plan, shard)
    tasks = [
        (pkg, [str(p) for p in paths], prefix)
        for _index, (pkg, paths, prefix) in selected
    ]
    context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(
        max_workers=workers, mp_context=context,
        initializer=_init_worker,
        initargs=(str(config_module.CONFIG_DIR), str(db_module.DATA_DIR),
                  rules, config, include_location),
    ) as pool:
        results: list[tuple[int, list[dict]]] = []
        for (index, _task), package_rows in zip(
                selected, pool.map(_scan_package_task, tasks, chunksize=1)):
            results.append((index, package_rows))
    return results

def scan_corpus_tasks(
    corpus: Path, sample: int = 1, jobs: int | None = None,
    include_location: bool = False, shard: tuple[int, int] | None = None,
) -> list[tuple[int, list[dict]]]:
    """Indexed per-package scan rows: the unit ``scan_corpus`` flattens.

    ``shard=(I, N)`` keeps tasks whose plan index is ``I mod N``; the
    index travels with each task so a caller can merge shards back into
    whole-corpus order.  Every task carries its precomputed novelty
    prefix, so sharding never changes a row.
    """
    ensure_default_configs()
    config = load_config()
    rules = load_rules()
    workers = _resolve_jobs(jobs)
    if workers <= 1:
        plan = _benign_plan(corpus, sample, config)
        return _scan_corpus_serial(plan, shard, rules, config, include_location)
    # Decide pattern safety on the idle parent; the forked workers inherit
    # the verdict.  The schema exists before workers open read connections.
    _precompile_patterns(rules)
    db_module.init_db()
    plan = _benign_plan(corpus, sample, config)
    return _scan_corpus_parallel(
        plan, shard, workers, rules, config, include_location
    )

def scan_corpus(
    corpus: Path, sample: int = 1, jobs: int | None = None,
    include_location: bool = False, shard: tuple[int, int] | None = None,
) -> list[dict]:
    """Scan every (or every *sample*-th) benign diff.

    Novelty is order-dependent, so the replay walks packages in a stable
    order - the same shape as ``rebaseline.py``.  Sampling keeps that
    property by thinning whole packages' diffs uniformly rather than
    reordering them.  ``jobs`` > 1 runs packages in worker processes: each
    package's diffs stay serial inside its worker and the global URL prefix
    is precomputed exactly, so the results are the serial results.
    ``include_location`` adds the finding's file and line to each entry.
    ``shard`` restricts the scan to one slice of the plan (see
    :func:`scan_corpus_tasks`); the merged shards equal the whole run.
    """
    if shard is None and _resolve_jobs(jobs) <= 1:
        ensure_default_configs()
        return _scan_corpus_serial_legacy(
            corpus, sample, load_config(), load_rules(), include_location)
    return [
        row
        for _index, rows in scan_corpus_tasks(
            corpus, sample, jobs, include_location, shard)
        for row in rows
    ]

def _benign_plan(
    corpus: Path, sample: int, config: dict
) -> list[tuple[str, list[Path], frozenset[str]]]:
    """Per-package diff lists plus each package's exact global-URL prefix.

    Walks the corpus once in the same order and through the same URL path
    ``scan_diff`` uses, so a worker starting at a package sees exactly the
    global novelty a serial run would have by then.  Within a package the
    diffs stay serial in the worker, so per-package novelty is preserved.
    """
    by_pkg = _ordered_benign_packages(corpus)
    plan: list[tuple[str, list[Path], frozenset[str]]] = []
    global_seen: set[str] = set()
    index = 0
    for pkg in sorted(by_pkg):
        selected: list[Path] = []
        additions: list[str] = []
        for path in sorted(by_pkg[pkg], key=lambda p: p.stem):
            index += 1
            if sample > 1 and index % sample:
                continue
            selected.append(path)
            text = path.read_text(errors="replace")
            additions.extend(
                normalize_url(url)
                for url in scored_source_urls(text, config, pkg)
            )
        if selected:
            plan.append((pkg, selected, frozenset(global_seen)))
        global_seen.update(additions)
    return plan

_WORKER_RULES: list[dict] | None = None

_WORKER_CONFIG: dict | None = None

_WORKER_INCLUDE_LOCATION = False

def _init_worker(
    config_dir: str, data_dir: str, rules, config, include_location: bool
) -> None:
    """Install the parent's shipped config and drop inherited state.

    The pool forks, so the parent's rule-safety verdicts and config paths
    are inherited; the database connection and the tokenizer worker pool
    are not safe to share across a fork and are reset here.  The parent's
    sandbox workers are left alone: their pids name live processes in the
    parent's table, and stopping one would kill the parent's pool.
    """
    from trustsight.db import _dependencies as db_deps

    global _WORKER_RULES, _WORKER_CONFIG, _WORKER_INCLUDE_LOCATION
    config_module.CONFIG_DIR = Path(config_dir)
    config_module._toml_cache.clear()
    db_module.DATA_DIR = Path(data_dir)
    db_deps._official_names = frozenset()
    cached = getattr(db_module._local, "cached", None)
    if cached is not None:
        try:
            cached[1].close()
        except Exception:
            pass
        db_module._local.cached = None
    # The parent ran ``init_db()`` before forking, so the schema already
    # exists at this same path.  Re-running it here is not harmless: its
    # ``DROP VIEW IF EXISTS ...; CREATE VIEW ...`` pair is not atomic, and
    # eight workers racing it intermittently killed one with
    # ``view gained_hosts_window already exists`` (a BrokenProcessPool).
    # Each worker opens its own lazy connection to the existing schema.
    reset_after_fork()
    reset_git_after_fork()
    _WORKER_RULES = rules
    _WORKER_CONFIG = config
    _WORKER_INCLUDE_LOCATION = include_location

def _precompile_patterns(rules) -> None:
    """Decide pattern safety once, single-threaded, before forking.

    The safety probe is wall-clock; under pool contention a shipped pattern
    can be refused in one worker and accepted in another (B1).  The parent's
    verdict is inherited by each forked worker, so every worker agrees.
    Generated patterns (R013, R047, R048, R152) are filled in first, or the
    placeholder would be vetted and the real pattern re-timed in every
    worker - exactly the R013 refusal this fixes.
    """
    resolve_generated_patterns(rules)
    precompile_patterns(r.get("pattern", "") for r in rules)
    precompile_structural_patterns()

def _malicious_row(group: str, path: Path, fact, expected: dict) -> dict:
    return {
        "group": group,
        "name": path.name,
        "score": fact.final_score,
        "fired": {e.rule_id for e in fact.score_breakdown},
        # A weight-0 finding is a reported fact, not a flag: H001 on a
        # justified SKIP says "this is a -git package's SKIP", which is
        # exactly what a must_not_fire label means to allow.
        "scored": {
            e.rule_id for e in fact.score_breakdown
            if e.weight != 0 or e.severity == "FATAL"
        },
        "expected": expected.get(path.name, {}),
    }

def _scan_malicious_task(task):
    group, path_str, expected = task
    path = Path(path_str)
    text = path.read_text(errors="replace")
    fact = scan_diff(text, rules=_WORKER_RULES, config=_WORKER_CONFIG,
                     package_name=path.stem, seen_urls={})
    return _malicious_row(group, path, fact, expected)

def scan_malicious(root: Path, jobs: int | None = None) -> list[dict]:
    """Scan the labelled malicious fixtures, carrying their expectations.

    The ``warm`` group is skipped: its rules read the dependency corpus and
    this is the cold scanner.  ``gate_d_series_warm`` scans it under the
    seeded corpus and asserts the cold half itself.  Fixtures are
    independent (each starts from an empty novelty state), so they run in
    parallel when ``jobs`` asks for it.
    """
    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    tasks = []
    for group in sorted(
            p for p in root.iterdir() if p.is_dir() and p.name != "warm"):
        expected_path = group / "expected.json"
        expected = json.loads(expected_path.read_text()) if expected_path.exists() else {}
        for path in sorted(group.glob("*.diff")):
            tasks.append((group.name, str(path), expected))

    workers = _resolve_jobs(jobs)
    if workers <= 1:
        return [
            _scan_malicious_task(task) for task in tasks
        ]
    _precompile_patterns(rules)
    db_module.init_db()
    context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(
        max_workers=workers, mp_context=context,
        initializer=_init_worker,
        initargs=(str(config_module.CONFIG_DIR), str(db_module.DATA_DIR),
                  rules, config, False),
    ) as pool:
        return list(pool.map(_scan_malicious_task, tasks, chunksize=1))

def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile; 0.0 for an empty sample."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(math.ceil(q * len(ordered))) - 1))
    return ordered[rank]

def pearson(xs: list[float], ys: list[float]) -> float:
    """Pearson correlation; 0.0 when either series has no variance."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    dx = [x - mean_x for x in xs]
    dy = [y - mean_y for y in ys]
    denom = math.sqrt(sum(d * d for d in dx)) * math.sqrt(sum(d * d for d in dy))
    if denom == 0:
        return 0.0
    return sum(a * b for a, b in zip(dx, dy)) / denom

def _is_attack_fixture(result: dict) -> bool:
    """True for a fixture that stands for a whole attack.

    Most synthetic fixtures are single-signal probes - "does H001 fire on a
    SKIP" - and a lone MEDIUM signal is *supposed* to score like an ordinary
    suspicious diff.  Including them would measure the unit fixtures, not
    the separation the gate is about.  What counts is the historical corpus
    (real incidents) plus any synthetic fixture whose own label claims a
    High-or-worse outcome.
    """
    if result["group"] == "holdout" or "control" in result["name"]:
        return False
    if result["expected"].get("known_gap"):
        return False
    if result["group"] == "historical":
        return True
    return (result["expected"].get("min_score") or 0) >= CRITICAL_MIN_SCORE

def _fixture_failures(result: dict) -> list[str]:
    expected = result["expected"]
    failures: list[str] = []
    for rule_id in expected.get("must_fire", []):
        if rule_id not in result["fired"]:
            failures.append(f"{result['name']}: {rule_id} did not fire")
    for rule_id in expected.get("must_not_fire", []):
        if rule_id in result["scored"]:
            failures.append(f"{result['name']}: {rule_id} scored")
    low = expected.get("min_score")
    if low is not None and result["score"] < low:
        failures.append(f"{result['name']}: score {result['score']} < {low}")
    high = expected.get("max_score")
    if high is not None and result["score"] > high:
        failures.append(f"{result['name']}: score {result['score']} > {high}")
    return failures

_GAP_PRIOR_RULES = frozenset({"COVERAGE", "SOURCE_BUCKET", "NOVELTY"})

def _gap_detected_by_another_rule(result: dict) -> list[str]:
    """Scored findings on a known-gap fixture whose named rule did not fire.

    The gap record names the rule that was *meant* to catch the shape.
    When a later rule catches it instead, ``must_fire`` still fails and the
    fixture sits filed under "we do not detect this" forever: that is how
    the array-subscript, nameref and command-substitution gaps survived
    after the crossfire family closed them.  A fixture that clears its
    score bar with a real finding is covered, whatever rule produced it.
    """
    expected = result["expected"]
    if not expected.get("known_gap"):
        return []
    must = expected.get("must_fire", [])
    if all(rule in result["fired"] for rule in must):
        # The named rule fired; the label's own check reports it.
        return []
    min_score = expected.get("min_score")
    if min_score is not None and result["score"] < min_score:
        return []
    return sorted(result["scored"] - _GAP_PRIOR_RULES)

_S_RULES = ("S001", "S002", "S003", "S004", "S005", "S006", "S007", "S008")

#: One source of truth: the escalation set lives in the scorer, so the
#: calibration cap and the runtime behaviour cannot disagree.
from trustsight.scoring import _META_ESCALATORS  # noqa: E402

X_RULES = tuple(f"X{i:03d}" for i in range(1, 32))

MAX_X_RATE_DRIFT = 0.002
