"""Regenerate ``docs/reference/rules/index.md`` from the category pages.

The index is a map, not content: its legend counts the members of
:class:`~trustsight.categories.RuleCategory`, and its quick-reference table
is one row per ``### Rxxx:`` heading found on the category pages. Both are
derived, so writing them by hand means two places to update and one of them
silently going stale.

``tests/test_docs.py`` fails if a rule is missing from the table, so this
script is what a rule author runs after adding the rule's section:

    python scripts/build_rules_index.py

The prose above the table is hand-written and is preserved verbatim between
the markers below.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.categories import RuleCategory, rules_in  # noqa: E402
from trustsight.registry import resolve  # noqa: E402

RULES_DIR = ROOT / "docs" / "reference" / "rules"
INDEX = RULES_DIR / "index.md"

LEGEND_START = "<!-- generated: legend -->"
LEGEND_END = "<!-- /generated: legend -->"
TABLE_START = "<!-- generated: catalog -->"
TABLE_END = "<!-- /generated: catalog -->"

HEADING = re.compile(r"^### ([A-Z]\d{3}):\s*(.*?)\s*(?:\{#([^}]+)\})?\s*$")
SEVERITY = re.compile(r"\b(FATAL|CRITICAL|HIGH|MEDIUM|LOW|INFO)\b")

SERIES_NAMES = {
    "C": "Integrity-change",
    "R": "Regex",
    "H": "Heuristic",
    "D": "Dependency",
    "S": "Sabotage",
    "X": "Crossfire",
    "W": "Unverifiable",
    "P": "Declared-practice",
    "M": "Meta",
    "E": "Entropy",
    "T": "Temporal",
    "G": "Correlation",
    "A": "Artifact",
    "I": "Indicator",
}


def _catalog() -> list[tuple[str, str, str, str, RuleCategory, str]]:
    """Every documented rule section, as (id, name, severity, series, category, anchor).

    One row per rule, not per heading: ``H026`` is documented twice (the
    per-package path and the corpus path), and the catalog is a list of
    rules, so the second section does not add a row.
    """
    rows = []
    seen: set[str] = set()
    for category in RuleCategory:
        page = RULES_DIR / category.doc_page
        if not page.exists():
            continue
        lines = page.read_text().split("\n")
        for index, line in enumerate(lines):
            match = HEADING.match(line)
            if not match:
                continue
            rule_id, name, anchor = match.group(1), match.group(2), match.group(3)
            if rule_id in seen:
                continue
            seen.add(rule_id)
            prefix = rule_id[0]
            series = SERIES_NAMES.get(prefix, prefix)
            rows.append(
                (rule_id, name, _severity(lines[index:]),
                 series, category, anchor or rule_id.lower())
            )
    # Series then number, from the one registry ordering, so the catalog and
    # every page index cannot disagree about where a rule sits.
    rows.sort(key=_order)
    return rows


def _order(row: tuple[str, str, str, str, RuleCategory, str]):
    """The registry sort key for a catalog row, anchor breaking ties."""
    rule = resolve(row[0])
    series, number, rule_id = rule.sort_key if rule else (row[3], int(row[0][1:]), row[0])
    return (series, number, rule_id, row[5])


def _severity(section: list[str]) -> str:
    """The severity a section declares, as a single word.

    Several rules carry a per-branch severity ("HIGH on replacement, MEDIUM
    on addition"); the table shows the worst one it opens with, which is
    what the full entry then qualifies.
    """
    for index, line in enumerate(section):
        # Stop at the next rule heading. A section with no severity line of
        # its own (a retired or reserved anchor) would otherwise inherit the
        # severity of whichever rule follows it, which is how H005 once
        # rendered as H008's MEDIUM.
        if index and line.startswith("### "):
            break
        # Two spellings: the list form (`- **Severity:** HIGH (weight 25)`)
        # and the reference form, where the severity opens the entry
        # (`**HIGH** (weight 25) - category evasion`).
        if line.startswith("- **Severity:**") or line.startswith("**"):
            found = SEVERITY.search(line)
            if found:
                return found.group(1)
            return "tiered" if "tiered" in line else "-"
    return "-"


def _replace(text: str, start: str, end: str, body: str) -> str:
    pattern = re.compile(
        rf"{re.escape(start)}\n.*?\n{re.escape(end)}", re.S
    )
    replacement = f"{start}\n{body}\n{end}"
    updated, count = pattern.subn(lambda _: replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"marker {start} not found in {INDEX}")
    return updated


PAGE_START = "<!-- generated: page-index -->"
PAGE_END = "<!-- /generated: page-index -->"
PAGE_INDEX_RE = re.compile(
    rf"{re.escape(PAGE_START)}\n.*?\n{re.escape(PAGE_END)}", re.S
)


def _page_blocks(catalog) -> dict[str, str]:
    """Page filename -> its generated index block, in catalog order.

    A category page is a flat run of `###` sections, so its table of
    contents is one long unstructured list and a reader looking for a
    specific rule has to scroll. The list below is an `##` section, which
    gives the page a second level, and it links straight to each anchor.
    """
    by_page: dict[str, list] = {}
    for rid, name, sev, _series, cat, anchor in catalog:
        by_page.setdefault(cat.doc_page, []).append((rid, name, sev, anchor))

    blocks = {}
    for page_name, rules in by_page.items():
        body = "\n".join(
            f"| [{rid}](#{anchor}) | {name} | {sev} |" for rid, name, sev, anchor in rules
        )
        blocks[page_name] = (
            f"{PAGE_START}\n"
            f"## Rules on this page\n\n"
            f"| Rule | Name | Severity |\n|---|---|---|\n{body}\n"
            f"{PAGE_END}"
        )
    return blocks


def render_page(text: str, block: str) -> str:
    """*text* with its generated index replaced by *block*.

    A page with no marker yet gets the block inserted before its first
    section, so the writer and the freshness check share one code path.
    """
    if PAGE_START in text:
        return PAGE_INDEX_RE.sub(lambda _: block, text, count=1)
    first = text.find("\n### ")
    if first == -1:
        return text
    return text[:first] + "\n" + block + "\n" + text[first:]


def render_index(text: str, catalog) -> str:
    """*text* with the generated legend and catalog replaced."""
    legend = "\n".join(
        f"| [{c.title}]({c.doc_page}) | `{c.value}` | {len(rules_in(c))} | {c.summary} |"
        for c in RuleCategory
    )
    table = "\n".join(
        f"| [{rid}]({cat.doc_page}#{anchor}) | {name} | {series} | {sev} | "
        f"[{cat.title}]({cat.doc_page}) |"
        for rid, name, sev, series, cat, anchor in catalog
    )
    text = _replace(
        text, LEGEND_START, LEGEND_END,
        "| Category | Slug | Rules | What a rule here claims |\n"
        "|----------|------|-------|-------------------------|\n"
        + legend,
    )
    return _replace(
        text, TABLE_START, TABLE_END,
        "| Id | Name | Series | Severity | Category |\n"
        "|----|------|--------|----------|----------|\n"
        + table,
    )


def main() -> None:
    catalog = _catalog()
    blocks = _page_blocks(catalog)

    for page_name, block in blocks.items():
        page = RULES_DIR / page_name
        if page.exists():
            page.write_text(render_page(page.read_text(), block))

    INDEX.write_text(render_index(INDEX.read_text(), catalog))

    print(f"{INDEX.relative_to(ROOT)}: {len(catalog)} rules across "
          f"{len(RuleCategory)} categories; {len(blocks)} on-page indexes")


if __name__ == "__main__":
    main()
