"""Assign opaque, permanent ``uid`` values to rules, append-only.

The uid table (``src/trustsight/registry_uids.json``) is the *identity*
record: a rule's uid never changes and is never reused, even if the rule is
renamed or retired.  This script only ever **adds** entries for ids found in
:data:`trustsight.categories.RULE_CATEGORIES`; it never rewrites or reorders
an existing uid, so re-running it is a no-op once every id has one.

The seed order is ``sorted(RULE_CATEGORIES)`` so the first run is
deterministic; after that, ids carry their assigned uid forever regardless of
what later rules are called.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trustsight.categories import RULE_CATEGORIES  # noqa: E402

OUT = ROOT / "src" / "trustsight" / "registry_uids.json"


def main() -> None:
    existing: dict[str, str] = {}
    if OUT.exists():
        existing = json.loads(OUT.read_text(encoding="utf-8"))

    highest = max((int(uid.split("-")[1]) for uid in existing.values()), default=0)
    for rule_id in sorted(RULE_CATEGORIES):
        if rule_id in existing:
            continue
        highest += 1
        existing[rule_id] = f"TS-{highest:04d}"

    OUT.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(existing)} uids in {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
