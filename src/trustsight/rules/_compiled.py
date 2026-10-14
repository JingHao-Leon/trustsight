"""Extracted from rules.py: _compiled."""

import re
from ..diffdoc import parse_diff_lines
from ..tokenizer import (
    split_lines,
)
from ..regex_safety import (
    BACKTRACK_BUDGET_S,
    backtracking_risk,
    has_nested_quantifier,
    is_superlinear,
)
from ._common import _log

__all__ = ['GENERATED_PATTERN_RULES', '_compiled', '_dynamic_pattern_is_unsafe', '_dynamic_pattern_verdict', '_pattern_cache', 'find_line_in_diff', 'precompile_patterns', 'precompile_shipped_patterns', 'precompile_structural_patterns', 'resolve_generated_patterns']

_pattern_cache: dict[str, "re.Pattern | None"] = {}

def _compiled(pattern: str, rule_id: str = ""):
    """Return the compiled form of *pattern*, or None if it is invalid.

    Every verdict is memoised, including a refusal.  The wall-clock checks
    (:data:`BACKTRACK_BUDGET_S`, :func:`~trustsight.regex_safety.is_superlinear`)
    are load-sensitive: the same pattern could be accepted on an idle machine
    and refused on a busy one, so the score of one input depended on what else
    the box was doing (B1).  Deciding once and caching the answer removes that.
    The reliability cost - one slow probe disabling a rule for the process - is
    paid down by :func:`precompile_patterns`, which vets every shipped pattern
    single-threaded before the analysis pool starts, when the machine is least
    contended.
    """
    try:
        return _pattern_cache[pattern]
    except KeyError:
        pass
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        _pattern_cache[pattern] = None
        return None

    def _refuse() -> None:
        # Named, truncated: a refused pattern stops matching silently, and
        # "some rule died" is not something an operator can act on.
        # `trustsight lint` reports the same condition as an ERROR.
        _log.debug(
            "refusing regex pattern with excessive backtracking risk%s: %.80s",
            f" (rule {rule_id})" if rule_id else "",
            pattern,
        )

    if has_nested_quantifier(pattern):
        _refuse()
        _pattern_cache[pattern] = None
        return None

    # Growth as well as absolute cost: a quadratic pattern with a small
    # constant sits under the budget at the probe length and still costs
    # seconds at a full line.
    risk = backtracking_risk(compiled)
    if risk > BACKTRACK_BUDGET_S:
        # Re-probe once.  The probe is wall-clock, so a transiently loaded
        # machine can overshoot for a single measurement on a safe pattern.
        risk = min(risk, backtracking_risk(compiled))
    if risk > BACKTRACK_BUDGET_S or is_superlinear(compiled):
        _refuse()
        _pattern_cache[pattern] = None
        return None

    _pattern_cache[pattern] = compiled
    return compiled

def precompile_patterns(patterns) -> None:
    """Vet every pattern once, single-threaded, before matching starts.

    ``review`` analyses packages in a pool, and the wall-clock probe that
    decides whether a pattern is safe is inflated by GIL contention.  Vetting
    here, before the pool, means the decision is made once from the least
    loaded measurement available and is then cached for every thread - so a
    rule cannot vanish for one package in a batch and not another.
    """
    for pattern in patterns:
        if pattern:
            _compiled(pattern)

def precompile_shipped_patterns() -> None:
    """Vet the shipped and generated rule patterns, single-threaded."""
    import tomllib

    from ..config import DEFAULT_RULES

    generated = tomllib.loads(DEFAULT_RULES).get("rules", [])
    resolve_generated_patterns(generated)
    precompile_patterns(r.get("pattern", "") for r in generated)

def precompile_structural_patterns() -> None:
    """Vet the operator's structural rule patterns, single-threaded.

    Same reason as :func:`precompile_shipped_patterns`: the wall-clock
    safety probe must not run under pool contention, or a structural rule
    could vanish for one package in a batch and not another.
    """
    from ..config import load_structural_rules

    precompile_patterns(r.get("pattern", "") for r in load_structural_rules())

_dynamic_pattern_verdict: dict[str, bool] = {}

def _dynamic_pattern_is_unsafe(pattern: str, compiled: re.Pattern) -> bool:
    """True when *pattern* must be matched as literal text."""
    verdict = _dynamic_pattern_verdict.get(pattern)
    if verdict is None:
        verdict = bool(
            has_nested_quantifier(pattern)
            or backtracking_risk(compiled) > BACKTRACK_BUDGET_S
            or is_superlinear(compiled)
        )
        # Bounded: the callers pass rule-shaped fragments, but the cache
        # must not become a way for a long diff to grow memory.
        if len(_dynamic_pattern_verdict) < 4096:
            _dynamic_pattern_verdict[pattern] = verdict
    return verdict

def find_line_in_diff(
    diff_text: str, pattern: str, prefix: str = r"\+"
) -> int | None:
    r"""The 1-based line number of the first ``+``/``-`` line matching *pattern*.

    *pattern* is regex syntax on purpose: callers pass things like
    ``SKIP|NONE`` and ``sha256sums\s*=\s*\(``. Callers that mean a literal
    escape it first.

    The subtlety is what happens when escaping was forgotten, or when a
    caller forwards package text. This used to compile the pattern
    unescaped, fall back to escaping only on ``re.error``, and run whatever
    compiled against every line - so a string that is *valid* regex was
    executed as one, and this is the single place in the program where a
    pattern is built at runtime rather than audited by
    ``scripts/regex_audit.py``. A supplied ``(a+)+$`` cost 5.6 seconds
    against one 24-character line, doubling every two characters.

    So a dynamic pattern is held to the same standard as a shipped one: if
    it backtracks, it is treated as the literal text it probably was.
    """
    def _compile(body: str):
        return re.compile(r"^" + prefix + r".*" + body, re.IGNORECASE)

    try:
        compiled = _compile(pattern)
        if _dynamic_pattern_is_unsafe(pattern, compiled):
            _log.warning(
                "refusing dynamic line pattern with excessive backtracking "
                "risk; matching it literally instead"
            )
            compiled = _compile(re.escape(pattern))
    except re.error:
        # An escaped fragment sliced mid-escape leaves a trailing backslash.
        compiled = _compile(re.escape(pattern))

    for index, line in enumerate(parse_diff_lines(split_lines(diff_text)).lines):
        if compiled.search(line.raw):
            return index + 1
    return None

GENERATED_PATTERN_RULES = ("R013", "R047", "R048", "R152")

def resolve_generated_patterns(rules: list[dict]) -> list[dict]:
    """Fill in the patterns that are generated rather than declared.

    R013 is assembled from Unicode data and R047/R048/R152 from config, so
    their TOML entries carry a placeholder and the real pattern only exists
    once this has run.

    A function rather than a loop inside `apply_rules` so that
    `scripts/regex_audit.py` can audit what actually runs. Those generated
    patterns were invisible to all three of the audit's collection
    strategies at once: not a TOML literal, not `re.compile("literal")` in
    the source, and not a module-level `re.Pattern`. R013 is the FATAL
    homoglyph rule, and R047/R048/R152 are built from operator config, so a
    config edit could have slowed the scan with no gate to catch it.
    """
    for rule in rules:
        if rule.get("id") == "R013":
            from ..unicode import R013_UNCONDITIONAL_PATTERN
            rule["pattern"] = (
                R013_UNCONDITIONAL_PATTERN
                + r"|(?<![^\x00-\x7F])[\u200B-\u200F\uFEFF](?![^\x00-\x7F])"
            )
        elif rule.get("id") == "R047":
            from ..config import _standard_port_pattern
            rule["pattern"] = _standard_port_pattern()
        elif rule.get("id") == "R048":
            from ..config import _free_registrar_tld_pattern
            rule["pattern"] = _free_registrar_tld_pattern()
        elif rule.get("id") == "R152":
            from ..config import _free_hosting_pattern
            rule["pattern"] = _free_hosting_pattern()
    return rules
