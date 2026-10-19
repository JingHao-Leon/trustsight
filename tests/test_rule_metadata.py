"""The documented rule metadata agrees with what the code emits.

``registry_meta.json`` is now the source for a rule's name and severity, and
the reference pages render from it.  These checks close the loop the other
way: for every rule whose emitters we can read statically, the documented
name and severity must be among the values the code actually emits, so the
registry cannot quietly describe a rule the analyser no longer has.

The scan is deliberately conservative.  A rule emitted only through a
computed id or a variable severity is skipped rather than guessed at; the
point is to catch drift on the rules we can see without inventing a second
parser for the ones we cannot.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

from trustsight.categories import RULE_CATEGORIES
from trustsight.config._default_rules import DEFAULT_RULES
from trustsight.registry import REGISTRY, SECTION_META

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "trustsight"

#: Files that name a rule in a sample or a lint template, not as an emitter.
_NOT_EMITTERS = {"contract.py", "lint.py"}

#: Rules whose documented name is an umbrella the emitters never use
#: verbatim: H078 documents one "signing key set changed" fact, but names
#: the replacement, addition and introduction paths separately.
_UMBRELLA_NAMES = {"H078"}

_SEVERITY = {"FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _emitted() -> dict[str, set[tuple[str, str]]]:
    """rule id -> the (name, severity) pairs statically present in source."""
    found: dict[str, set[tuple[str, str]]] = {}

    def record(rule_id, name, severity) -> None:
        if rule_id in RULE_CATEGORIES and name and severity in _SEVERITY:
            found.setdefault(rule_id, set()).add((name, severity))

    for rule in tomllib.loads(DEFAULT_RULES)["rules"]:
        record(rule.get("id"), rule.get("name"), rule.get("severity"))

    for path in SOURCE.rglob("*.py"):
        if path.name in _NOT_EMITTERS:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:  # pragma: no cover - source always parses
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                fields = {
                    key.value: _literal(value)
                    for key, value in zip(node.keys, node.values)
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
                record(fields.get("rule_id"), fields.get("name"), fields.get("severity"))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "add"
            ):
                args = [_literal(arg) for arg in node.args]
                if args:
                    record(args[0], args[1] if len(args) > 1 else None,
                           args[2] if len(args) > 2 else None)
    return found


def _canonical() -> dict[str, dict]:
    return {
        entry["uid"]: entry
        for entry in SECTION_META.values()
        if entry.get("canonical")
    }


def test_every_rule_has_a_documented_name():
    named = _canonical()
    missing = sorted(rule.id for rule in REGISTRY.all() if not named.get(rule.uid, {}).get("name"))
    assert missing == [], f"rules with no documented name: {missing}"


def test_the_documented_name_is_one_the_code_emits():
    emitted = _emitted()
    named = _canonical()
    wrong = []
    for rule in REGISTRY.all():
        pairs = emitted.get(rule.id)
        if not pairs:
            continue
        documented = named.get(rule.uid, {}).get("name")
        names = {name for name, _severity in pairs}
        if documented not in names and rule.id not in _UMBRELLA_NAMES:
            wrong.append((rule.id, documented, sorted(names)))
    assert wrong == [], (
        "documented name is never emitted; update registry_meta.json: " f"{wrong}"
    )


def test_the_documented_severity_covers_every_emitted_one():
    emitted = _emitted()
    named = _canonical()
    wrong = []
    for rule in REGISTRY.all():
        pairs = emitted.get(rule.id)
        if not pairs:
            continue
        text = named.get(rule.uid, {}).get("severity_text") or ""
        documented = {word for word in _SEVERITY if word in text}
        if not documented:
            continue  # no documented severity yet; skip rather than guess
        extra = {severity for _name, severity in pairs} - documented
        if extra:
            wrong.append((rule.id, sorted(extra), text))
    assert wrong == [], (
        "code emits a severity the docs do not describe; update "
        f"registry_meta.json: {wrong}"
    )


def test_scan_sees_a_useful_share_of_the_rules():
    """A silent regression in the scanner would make the checks vacuous."""
    seen = set(_emitted())
    assert len(seen) >= 150, f"metadata scan only reached {len(seen)} rules"
    assert {"R001", "H091", "C014", "G001", "H078"} <= seen
