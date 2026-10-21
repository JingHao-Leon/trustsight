"""Audit shipped regex patterns against bounded adversarial probes.

This is intentionally dependency-free. It does not replace Python's ``re``
engine; it makes the current worst-case checks visible for both configured
rules and literal patterns compiled in the source tree.
"""

from __future__ import annotations

import ast
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "trustsight"
sys.path.insert(0, str(ROOT / "src"))

from trustsight.config import DEFAULT_RULES  # noqa: E402
from trustsight.lint import (  # noqa: E402
    _BACKTRACK_BUDGET_S,
    _backtracking_risk,
)
from trustsight.regex_safety import (  # noqa: E402
    BACKTRACK_PROBES,
    derived_probes,
    is_superlinear,
)


@dataclass(frozen=True)
class PatternAudit:
    source: str
    pattern: str
    worst_seconds: float
    error: str = ""
    #: ``match``/``fullmatch`` inline calls never search past position zero,
    #: so they are measured with the method they actually use.
    anchored: bool = False

    @property
    def passed(self) -> bool:
        return not self.error and self.worst_seconds <= _BACKTRACK_BUDGET_S


def _literal_patterns() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "compile":
                continue
            if not isinstance(func.value, ast.Name) or func.value.id != "re":
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            if isinstance(node.args[0].value, str):
                found.append((f"{path.relative_to(ROOT)}:{node.lineno}", node.args[0].value))
    return found


#: Inline calls that compile an implicit pattern.  ``re.match`` and
#: ``re.fullmatch`` are anchored at position zero; the rest try every start.
_INLINE_METHODS = frozenset({
    "match", "search", "fullmatch", "findall", "finditer", "sub", "subn",
    "split",
})
_ANCHORED_INLINE_METHODS = frozenset({"match", "fullmatch"})


def _inline_patterns() -> list[tuple[str, str, str | None]]:
    """Literal patterns passed straight to ``re.match/search/...``.

    The AST scan in :func:`_literal_patterns` only sees ``re.compile``.  A
    literal handed to ``re.search`` is compiled implicitly and cached by the
    ``re`` module, so it was invisible to every collection strategy - and the
    coverage gate could not tell the difference between "audited and safe"
    and "never looked at".  Returns ``(source, pattern, anchored)``.
    """
    found: list[tuple[str, str, bool]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in _INLINE_METHODS:
                continue
            if not isinstance(func.value, ast.Name) or func.value.id != "re":
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            if isinstance(node.args[0].value, str):
                found.append((
                    f"{path.relative_to(ROOT)}:{node.lineno}:inline",
                    node.args[0].value,
                    func.attr if func.attr in _ANCHORED_INLINE_METHODS else None,
                ))
    return found


def _runtime_patterns() -> list[tuple[str, str]]:
    """Every compiled pattern reachable from an imported module.

    The AST scan above only sees ``re.compile("literal")``. A pattern
    assembled from parts - ``re.compile(_WRITE_CMD_START + r"tee ...")`` -
    is a ``BinOp`` rather than a ``Constant``, so it was skipped silently,
    and shared command-start prefixes are exactly the idiom the newer rule
    modules are built from. That was 44 of 246 patterns, 18%, concentrated
    in ``sabotage``, ``persistence`` and ``crossfire``.

    Importing to enumerate is the only way to see an assembled pattern,
    because its text does not exist until it is built.
    """
    import importlib

    found: list[tuple[str, str]] = []
    seen: set[int] = set()
    for path in sorted(SRC.rglob("*.py")):
        parts = [
            part
            for part in path.relative_to(SRC).with_suffix("").parts
            if part != "__init__"
        ]
        # `cli` builds a Typer app and `__main__` runs it on import.
        if not parts or parts[0] == "cli" or "__main__" in parts:
            continue
        name = "trustsight." + ".".join(parts)
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        for attr, value in vars(module).items():
            candidates = (
                [value]
                if isinstance(value, re.Pattern)
                else list(value)
                if isinstance(value, (list, tuple, frozenset, set))
                else []
            )
            for item in candidates:
                if isinstance(item, re.Pattern) and id(item) not in seen:
                    seen.add(id(item))
                    found.append((f"{name}.{attr}", item.pattern))
    return found


def _configured_patterns() -> list[tuple[str, str]]:
    """The TOML rules, with generated patterns resolved as they run.

    R013, R047 and R048 carry a placeholder in the TOML and are assembled
    at match time from Unicode data and from config. Auditing the
    placeholder audits a pattern that never executes, so this resolves them
    through the same function `rules.apply_rules` uses.
    """
    import tomllib

    from trustsight.rules import resolve_generated_patterns

    rules = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(rules)
    return [(f"DEFAULT_RULES:{rule.get('id', '<unknown>')}", rule["pattern"])
            for rule in rules if isinstance(rule.get("pattern"), str)]



#: How many times a pattern that appears over budget is re-measured. Only
#: the *minimum* counts: contention on a loaded machine inflates a timing
#: and never deflates one, so a genuinely catastrophic pattern is slow on
#: every attempt while a linear one measured next to a busy test suite is
#: fast as soon as it gets the CPU. This ran green alone and red inside the
#: full suite, which is a property of the machine rather than of the rule.
_RETRIES_WHEN_OVER_BUDGET = 3


def _stable_backtracking_risk(compiled) -> float:
    """The worst probe time, re-measured while it looks over budget."""
    worst = _backtracking_risk(compiled)
    for _ in range(_RETRIES_WHEN_OVER_BUDGET - 1):
        if worst <= _BACKTRACK_BUDGET_S:
            return worst
        worst = min(worst, _backtracking_risk(compiled))
    return worst


def _configured_fragment_patterns() -> list[tuple[str, str]]:
    """Patterns assembled from ``patterns.toml``/``hosts.toml`` at runtime.

    These are compiled inside functions, so they are neither module-level
    ``re.Pattern`` objects nor ``re.compile("literal")`` calls.  Config is
    operator-trusted, but a malformed fragment compiled here can still make
    one package's line cost seconds, and previously no gate looked at them.
    Each producer is the same function the analysis calls, so the audit
    measures the text that actually runs.
    """
    from contextlib import ExitStack
    from unittest.mock import patch

    from trustsight.analysis import build, composition, network
    from trustsight.analysis.delivery import _recon

    producers = {
        "covert_egress": lambda: network._covert_clients(None),
        "parse_time_fetch": lambda: network._parse_time_fetch_patterns(),
        "upload_flags": lambda: network._upload_flags(),
        "foreign_pkg": lambda: build._foreign_pkg_re(),
        "obfuscation": lambda: build._obfuscation_indicators(),
        "reconstructs_to_action": lambda: build._reconstructs_to_action_re(),
        "recon": lambda: composition._recon_probes(),
        "anti_analysis": lambda: _recon._anti_analysis_probes(),
    }

    found: list[tuple[str, str]] = []
    # Read the shipped defaults, not the operator's already-written
    # patterns.toml.  That file is written once at install and keeps the
    # spelling it was written with, so auditing it would report the state of
    # an untracked file instead of what this build ships (the same split the
    # shipped-rule test documents).
    with ExitStack() as stack:
        for module in (build, composition, network, _recon):
            if hasattr(module, "load_patterns"):
                stack.enter_context(
                    patch.object(module, "load_patterns", lambda: {"patterns": {}}))
        stack.enter_context(
            patch.object(network, "load_hosts", lambda: {"hosts": {}}))

        for label, produce in producers.items():
            try:
                values = produce()
            except Exception:  # noqa: BLE001 - a broken config is another gate's job
                continue
            if isinstance(values, re.Pattern):
                values = [values]
            for index, value in enumerate(values):
                if isinstance(value, re.Pattern):
                    found.append(
                        (f"config-fragment:{label}:{index}", value.pattern))
    return found


def _anchored_risk(compiled: re.Pattern, method: str) -> float:
    """The worst probe time when the caller only matches at position zero."""
    worst = 0.0
    probe_fn = getattr(compiled, method)
    for probe in BACKTRACK_PROBES + derived_probes(compiled.pattern):
        started = time.process_time()
        try:
            probe_fn(probe)
        except (RecursionError, MemoryError):
            return _BACKTRACK_BUDGET_S * 100
        worst = max(worst, time.process_time() - started)
        if worst > _BACKTRACK_BUDGET_S:
            return worst
    return worst


def _stable_anchored_risk(compiled: re.Pattern, method: str) -> float:
    worst = _anchored_risk(compiled, method)
    for _ in range(_RETRIES_WHEN_OVER_BUDGET - 1):
        if worst <= _BACKTRACK_BUDGET_S:
            return worst
        worst = min(worst, _anchored_risk(compiled, method))
    return worst


def audit_patterns() -> list[PatternAudit]:
    audits: list[PatternAudit] = []
    # Keyed on the pattern text, not on where it was found. The same
    # pattern is reached as a source literal and again as a live object,
    # and auditing it twice under two labels only inflates the count.  A
    # pattern seen both anchored and unanchored is measured unanchored:
    # the stricter reading is the one that protects every caller.
    patterns: dict[str, tuple[str, str | None]] = {}
    for source, pattern in (
        _configured_patterns()
        + _literal_patterns()
        + _runtime_patterns()
        + _configured_fragment_patterns()
    ):
        patterns.setdefault(pattern, (source, None))
    for source, pattern, method in _inline_patterns():
        if pattern in patterns:
            previous_source, previous_method = patterns[pattern]
            # An unanchored use wins; between two anchored uses ``match`` is
            # the more conservative measurement.
            if previous_method is None or method is None:
                patterns[pattern] = (previous_source, None)
            else:
                patterns[pattern] = (previous_source, "match")
        else:
            patterns[pattern] = (source, method)

    for pattern, (source, method) in patterns.items():
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            if method is not None:
                # ``search``-style growth does not describe a ``match``
                # caller; measure the method it actually uses.
                worst = _stable_anchored_risk(compiled, method)
                audits.append(PatternAudit(source, pattern, worst,
                                           anchored=True))
                continue
            worst = _stable_backtracking_risk(compiled)
            # Growth as well as absolute cost, matching `rules._compiled`:
            # a quadratic pattern with a small constant sits under the
            # budget at the probe length and costs seconds at a full line.
            if worst <= _BACKTRACK_BUDGET_S and is_superlinear(compiled):
                audits.append(PatternAudit(
                    source, pattern, worst,
                    "cost grows faster than input length",
                ))
            else:
                audits.append(PatternAudit(source, pattern, worst))
        except re.error as exc:
            audits.append(PatternAudit(source, pattern, 0.0, f"compile: {exc}",
                                       method is not None))
    return audits


def main() -> int:
    audits = audit_patterns()
    failures = [audit for audit in audits if not audit.passed]
    for audit in audits:
        status = "PASS" if audit.passed else "FAIL"
        print(f"{status} {audit.source} {audit.worst_seconds * 1000:.2f}ms")
        if audit.error:
            print(f"  {audit.error}")
    print(f"{len(audits) - len(failures)}/{len(audits)} regex patterns passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
