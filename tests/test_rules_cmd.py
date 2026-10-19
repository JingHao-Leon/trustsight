"""``trustsight rules``: the registry, in its one shared order.

No pacman needed - the command only reads the rule registry - so this runs
everywhere, unlike ``tests/test_cli.py``.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from trustsight.categories import RuleCategory
from trustsight.cli import app
from trustsight.registry import REGISTRY

runner = CliRunner()


def test_rules_lists_every_rule_in_registry_order():
    result = runner.invoke(app, ["rules", "--json"])
    assert result.exit_code == 0, result.stderr
    rows = json.loads(result.stdout)
    assert [row["id"] for row in rows] == [rule.id for rule in REGISTRY.all()]


def test_rules_carry_uid_and_status():
    rows = json.loads(runner.invoke(app, ["rules", "--json"]).stdout)
    assert all(row["uid"].startswith("TS-") for row in rows)
    assert {row["status"] for row in rows} <= {"live", "anchor"}


def test_rules_category_filter():
    result = runner.invoke(app, ["rules", "--json", "--category", "correlation"])
    assert result.exit_code == 0, result.stderr
    rows = json.loads(result.stdout)
    assert rows
    assert {row["category"] for row in rows} == {"correlation"}
    expected = [rule.id for rule in REGISTRY.in_category(RuleCategory.CORRELATION)]
    assert [row["id"] for row in rows] == expected


def test_rules_rejects_an_unknown_category():
    result = runner.invoke(app, ["rules", "--category", "nope"])
    assert result.exit_code == 2


def test_rules_plain_output_lists_ids():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "R001" in result.stdout and "TS-" in result.stdout
