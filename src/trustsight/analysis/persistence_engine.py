"""The persistence engine: write-target + location-class predicates as data.

Addendum 3 Phase 4 consolidates the "write to a sensitive location, with a
declaration check" rules onto one path-classification table.  This module owns
the :data:`PERSISTENCE_INSTANCES` table and the predicates; the shared
:class:`~trustsight.analysis.edges.GraphContext` supplies the resolved lines,
scope resolver and heredoc bodies, so no rule rebuilds them.

Rule ids, severities and finding text are unchanged.  H004/H017/H023 (the
command/declaration arm, not path classification) and the delivery-side
carrier rules H084/H085/H089/H093/H095 stay on their own surfaces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from ..deps import _strip_comment
from ..rules import _classify_line_context
from .build import (
    _HOOK_EXEC_RE,
    _INSTALL_HOOKS,
    _added_line_number,
    _network_fetch_url,
    _sudo_escalates,
)
from .delivery import (
    _SCOPE_FUNCTIONS,
    _collect_executions,
    _norm_path,
    _printed_heredoc_body_indices,
)
from .edges import GraphContext
from .persistence import (
    _BUILD_TIME_FUNCTIONS,
    _DEVICE_TARGET_RE,
    _ES_RE,
    _HOME_PREFIX_RE,
    _INSTALL_SCRIPTLETS,
    _MKTEMP_RE,
    _PACMAN_HOOK_RE,
    _PLAIN_ABS_PATH_RE,
    _RC_BASENAME_RE,
    _RUNTIME_WRITABLE_RE,
    _WW_CD_RE,
    _WW_DIR_RE,
    _is_staged,
    _raw_targets,
)


@dataclass(frozen=True)
class PersistenceInstance:
    """One persistence rule's predicate row."""

    rule_id: str
    name: str
    location_class: str
    declaration_check: bool
    severity: str
    doc: str
    fixtures: tuple[str, ...]
    emitter: Callable[[GraphContext, Callable], None]


def emit_systemd_unit(ctx: GraphContext, add: Callable) -> None:
    """H039: a systemd unit whose ExecStart points at a runtime-writable path.

    Scans unit *content* (the ExecStart line itself, which can live in a
    heredoc body), so no scope/heredoc filter applies.
    """
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+"):
            continue
        m = _ES_RE.match(line[1:])
        if not m:
            continue
        target = m.group(1).strip("\"'")
        if _RUNTIME_WRITABLE_RE.search(target):
            add("H039", "Systemd ExecStart From Runtime-Writable Path", "HIGH",
                "persistence",
                f"systemd unit ExecStart points at runtime-writable path: {target}",
                line=i + 1, exec_target=target)
            return


def emit_pacman_hook(ctx: GraphContext, add: Callable) -> None:
    """H062: a pacman hook installed into the libalpm hook directory."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            if _PACMAN_HOOK_RE.search(_norm_path(t)):
                add("H062", "Pacman Hook Installed", "MEDIUM", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() installs a pacman hook: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return


def emit_home_rc(ctx: GraphContext, add: Callable) -> None:
    """H032: a write into a user's home or shell rc file."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        for t in _raw_targets(_strip_comment(line[1:])):
            t_clean = t.strip().strip("\"'")
            if _is_staged(t_clean):
                continue
            base = os.path.basename(t_clean)
            if _HOME_PREFIX_RE.search(t_clean) or _RC_BASENAME_RE.match(base):
                in_scriptlet = ctx.scopes.direct(i) in _INSTALL_SCRIPTLETS
                severity = "CRITICAL" if in_scriptlet else "HIGH"
                add("H032", "Write To User Home Or RC", severity, "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() writes into the user's home/rc: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return


def emit_worldwritable(ctx: GraphContext, add: Callable) -> None:
    """H038: work staged in a world-writable directory."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in ctx.heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if _MKTEMP_RE.search(body):
            continue
        for t in _raw_targets(body):
            if _WW_DIR_RE.search(t.strip().strip("\"'")):
                add("H038", "World-Writable Staging", "HIGH", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() stages work in a world-writable path: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return
        for t in _collect_executions(body):
            if _WW_DIR_RE.search(t):
                add("H038", "World-Writable Staging", "HIGH", "persistence",
                    f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() executes from a world-writable path: {t}",
                    line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), path=t)
                return
        if _WW_CD_RE.search(body):
            add("H038", "World-Writable Staging", "HIGH", "persistence",
                f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() works from a world-writable directory: {body.strip()[:80]}",
                line=i + 1, position=ctx.scopes.within(i, _SCOPE_FUNCTIONS), body=body.strip()[:80])
            return


def emit_outside_staging(ctx: GraphContext, add: Callable) -> None:
    """H076: a build-time function writes outside the staging root."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+"):
            continue
        fn = ctx.scopes.within(i, _BUILD_TIME_FUNCTIONS)
        if fn is None:
            if ctx.scopes.direct(i) is not None:
                continue
            fn = "top level"
        if i in ctx.heredoc_body:
            continue
        for target in _raw_targets(_strip_comment(line[1:])):
            path = target.strip().strip("\"'")
            if _is_staged(path) or _DEVICE_TARGET_RE.match(path):
                continue
            if not _PLAIN_ABS_PATH_RE.match(path):
                continue
            add("H076", "Build Writes Outside Staging Root", "HIGH",
                "persistence",
                f"{fn}() writes to {path}, outside $pkgdir/$srcdir",
                line=i + 1, position=fn, path=path)
            return


def emit_sudo(ctx: GraphContext, add: Callable) -> None:
    """H004: a build/install function escalates privilege."""
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        body = _strip_comment(line[1:])
        if _sudo_escalates(body):
            add("H004", "Privilege Escalation", "CRITICAL", "privilege",
                f"{ctx.scopes.label(i, _SCOPE_FUNCTIONS)}() escalates privilege: "
                f"{body.strip()[:80]}",
                line=_added_line_number(ctx.diff_text, body.strip()[:30]),
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            return


def emit_install_hook(ctx: GraphContext, add: Callable) -> None:
    """H017: an install hook fetches or executes."""
    context = _classify_line_context(ctx.lines)
    printed_heredoc = _printed_heredoc_body_indices(ctx.lines)
    for i, line in enumerate(ctx.lines):
        if not line.startswith("+") or not ctx.scopes.within(i, _INSTALL_HOOKS):
            continue
        if context.get(i) == "message" or i in printed_heredoc:
            continue
        body = _strip_comment(line)
        if _network_fetch_url(body) or _HOOK_EXEC_RE.search(body):
            add("H017", "Install Hook Fetches Or Executes", "HIGH", "installer",
                f"{ctx.scopes.label(i, _INSTALL_HOOKS)}() runs as root and contains: {body.strip()[:80]}",
                position=ctx.scopes.direct(i), body=body.strip()[:80])
            break


#: Dispatch order mirrors the historical emission order so finding order is
#: preserved.  H042 (hidden drop) is intentionally absent here - it is the
#: quietest rule and is registered in the edge engine.
PERSISTENCE_INSTANCES: tuple[PersistenceInstance, ...] = (
    PersistenceInstance("H039", "Systemd ExecStart From Runtime-Writable Path",
                        "runtime_writable", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/test_phase3.py",), emit_systemd_unit),
    PersistenceInstance("H062", "Pacman Hook Installed", "pacman_hook", False,
                        "MEDIUM", "docs/reference/rules/install-and-persist.md",
                        ("tests/test_phase3.py",), emit_pacman_hook),
    PersistenceInstance("H032", "Write To User Home Or RC", "home_rc", False,
                        "HIGH/CRITICAL", "docs/reference/rules/install-and-persist.md",
                        ("tests/test_phase3.py",), emit_home_rc),
    PersistenceInstance("H038", "World-Writable Staging", "world_writable",
                        False, "HIGH",
                        "docs/reference/rules/staging-and-recon.md",
                        ("tests/test_phase3.py",), emit_worldwritable),
    PersistenceInstance("H076", "Build Writes Outside Staging Root",
                        "absolute_outside", False, "HIGH",
                        "docs/reference/rules/staging-and-recon.md",
                        ("tests/test_phase3.py",), emit_outside_staging),
    PersistenceInstance("H004", "Privilege Escalation", "privilege", False,
                        "CRITICAL", "docs/reference/rules/fetch-and-execution.md",
                        ("tests/test_rules.py",), emit_sudo),
    PersistenceInstance("H017", "Install Hook Fetches Or Executes",
                        "install_hook", False, "HIGH",
                        "docs/reference/rules/install-and-persist.md",
                        ("tests/test_deps_rules.py",), emit_install_hook),
)


def run_persistence_instances(
    ctx: GraphContext, add: Callable, *, only: frozenset[str] | None = None
) -> None:
    """Dispatch the persistence predicates over *ctx*."""
    for instance in PERSISTENCE_INSTANCES:
        if only is not None and instance.rule_id not in only:
            continue
        instance.emitter(ctx, add)
