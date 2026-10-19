"""One-time split of the rule pages into per-section sources.

Phase 3b makes the rule bodies generated: each ``###`` section moves to its
own file under ``docs_src/sections/`` keyed by its anchor, the page prose
above the generated index moves to ``docs_src/pages/``, and the order the
sections appear in is recorded in ``docs_src/layout.json``.
``scripts/build_rules_index.py`` then reassembles every page from those
sources, so a display-id rename (Phase 5) rewrites every heading from the
registry instead of 266 hand edits.

The section source carries the immutable identity: ``uid`` (the permanent
handle), ``name`` and ``anchor``.  The ``###`` heading itself is *not*
stored - the generator writes it from the current id, so ``H026``'s two
sections (the per-package and corpus paths) both follow the rule while
keeping distinct anchors.

    uv run python scripts/split_rule_sources.py

Refuses to run twice unless ``--force``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.categories import RuleCategory  # noqa: E402
from trustsight.registry import resolve  # noqa: E402

RULES_DIR = ROOT / "docs" / "reference" / "rules"
SRC = ROOT / "docs_src"
PAGES = SRC / "pages"
SECTIONS = SRC / "sections"
LAYOUT = SRC / "layout.json"

PAGE_START = "<!-- generated: page-index -->"
PAGE_END = "<!-- /generated: page-index -->"
HEADING = re.compile(r"^### ([A-Z]\d{3}):\s*(.*?)\s*(?:\{#([^}]+)\})?\s*$")


def main() -> None:
    if SRC.exists() and "--force" not in sys.argv:
        raise SystemExit(f"{SRC} already exists; pass --force to overwrite")
    PAGES.mkdir(parents=True, exist_ok=True)
    SECTIONS.mkdir(parents=True, exist_ok=True)

    layout: dict[str, list[str]] = {}
    written = 0
    for category in RuleCategory:
        page = RULES_DIR / category.doc_page
        if not page.exists():
            continue
        text = page.read_text()
        if PAGE_START in text:
            header = text[: text.index(PAGE_START)].rstrip()
            after = text[text.index(PAGE_END) + len(PAGE_END):]
            body = after
        else:
            cut = text.find("\n### ")
            header, body = text[:cut].rstrip(), text[cut:]

        (PAGES / category.doc_page).write_text(header + "\n")

        lines = body.split("\n")
        heads = [i for i, line in enumerate(lines) if HEADING.match(line)]
        anchors = []
        for n, start in enumerate(heads):
            end = heads[n + 1] if n + 1 < len(heads) else len(lines)
            section = "\n".join(lines[start:end]).rstrip()
            chunk = section.split("\n")
            match = HEADING.match(chunk[0])
            rule_id, name, anchor = match.group(1), match.group(2), match.group(3)
            anchor = anchor or rule_id.lower()
            rule = resolve(rule_id)
            if rule is None:
                raise SystemExit(f"{page.name}: {rule_id} is not a registered rule")
            section_body = "\n".join(chunk[1:]).strip("\n")
            (SECTIONS / f"{anchor}.md").write_text(
                f"<!-- uid: {rule.uid} -->\n"
                f"<!-- name: {name} -->\n"
                f"<!-- anchor: {anchor} -->\n\n"
                f"{section_body}\n"
            )
            anchors.append(anchor)
            written += 1

        layout[category.doc_page] = anchors

    LAYOUT.write_text(json.dumps(layout, indent=2) + "\n")
    print(f"split {written} sections across {len(layout)} pages into {SRC}")


if __name__ == "__main__":
    main()
