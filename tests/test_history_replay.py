"""Addendum 3: the history-exercising corpus must replay as committed.

The stateless benign corpus never fires the observation-history rules, so
their detection had no test that exercised it.  Each history cycle asserts
the exact rule-id set it fires, so a drift in H026/H044, H045/H073,
H052/H053/H055/H059/H073/H074 fails here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "harness"))

from history_replay import compare, replay  # noqa: E402

_ROWS = replay()


def test_every_history_cycle_replays_as_committed():
    assert compare(_ROWS) == []


def test_the_corpus_exercises_the_audited_pairs():
    """The point of the corpus: each audited pair has a cycle that co-fires."""
    pairs = (("H026", "H044"), ("H045", "H073"), ("H053", "H059"))
    fired = {row["name"]: set(row["fired"]) for row in _ROWS}
    for left, right in pairs:
        assert any({left, right} <= ids for ids in fired.values()), (
            f"no cycle fires both {left} and {right}")
