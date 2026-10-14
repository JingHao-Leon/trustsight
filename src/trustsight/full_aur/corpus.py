"""The Class-D corpus sweep, now a thin facade over the temporal engine.

The detectors themselves live in :mod:`~trustsight.full_aur.temporal_engine`
(of the H-series reduction): the history-backed rules share one
:class:`~trustsight.full_aur.temporal_engine.HistorySnapshot` and are
dispatched from one instance table.  This module keeps the historical import
surface (``run_corpus_sweep``, ``source_repos_from_pkgbuild``) so callers do
not move.

All detectors are silent when there is no prior snapshot (``old_meta is
None``): the Class D calibration gate is ``fire_rate(no_baseline) == 0``.
"""

from .temporal_engine import (  # noqa: F401
    GRAPH_INSTANCES,
    PER_PACKAGE_INSTANCES,
    HistorySnapshot,
    run_corpus_sweep,
    run_cycle_instances,
    source_repos_from_pkgbuild,
)

__all__ = [
    "HistorySnapshot",
    "run_corpus_sweep",
    "run_cycle_instances",
    "source_repos_from_pkgbuild",
]
