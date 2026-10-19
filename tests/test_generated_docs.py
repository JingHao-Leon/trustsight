"""The generated docs tables cannot go stale.

``index.md``'s legend and catalog and every category page's on-page index are
written by ``scripts/build_rules_index.py``.  These render them from the pages
on disk and assert the files already match, so a rule added without running
the generator fails here instead of shipping a table that disagrees with the
pages.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from trustsight.categories import RULE_CATEGORIES

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_rules_index.py"


def _generator():
    spec = importlib.util.spec_from_file_location("build_rules_index", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_catalog_lists_each_registered_rule_once():
    ids = [row[0] for row in _generator()._catalog()]
    assert len(ids) == len(set(ids)), "a rule is listed twice in the catalog"
    assert set(ids) == set(RULE_CATEGORIES)


def test_index_matches_the_generator():
    build = _generator()
    on_disk = build.INDEX.read_text()
    assert on_disk == build.render_index(on_disk, build._catalog()), (
        "docs/reference/rules/index.md is stale; "
        "run python scripts/build_rules_index.py"
    )


def test_every_page_index_matches_the_generator():
    build = _generator()
    blocks = build._page_blocks(build._catalog())
    stale = []
    for page_name, block in blocks.items():
        text = (build.RULES_DIR / page_name).read_text()
        if text != build.render_page(text, block):
            stale.append(page_name)
    assert stale == [], (
        f"stale on-page indexes: {stale}; "
        "run python scripts/build_rules_index.py"
    )
