"""Extracted from structural.py: _hooks."""

import re
from ..persistence import (
    _HOME_PREFIX_RE,
    _raw_targets,
    _WW_DIR_RE,
)
from ...findings import stamp
from ...line_lex import strip_comment
from ...recipedoc import parse_recipe
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines

__all__ = ['_HOOK_INTERPRETER_RE', '_ROOT_HOME_RE', '_RUNTIME_USER_RE', '_XDG_PREFIX_RE', '_hook_names', '_user_writable_target', 'install_script_findings', 'partial_install_files']

_HOOK_INTERPRETER_RE = re.compile(
    r"(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:ba|z|da|k|a|mk|pdk|ya|po)?sh\b(?!\s*[=<])"
    r"|(?:^|[;&|(])\s*(?:/(?:usr/)?bin/)?"
    r"(?:python[23]?|perl|ruby|node|php)\b",
    re.IGNORECASE | re.MULTILINE,
)

_XDG_PREFIX_RE = re.compile(r"^\$?\{?XDG_[A-Z_]+\}?(?:/|$)")

_RUNTIME_USER_RE = re.compile(r"^/run/user/")

_ROOT_HOME_RE = re.compile(r"^/root(?:/|$)")

def _user_writable_target(target: str) -> bool:
    value = target.strip().strip("\"'")
    return bool(
        _HOME_PREFIX_RE.match(value)
        or _WW_DIR_RE.match(value)
        or _XDG_PREFIX_RE.match(value)
        or _RUNTIME_USER_RE.match(value)
        or _ROOT_HOME_RE.match(value)
    )

def _hook_names(recipe) -> list[str]:
    return [
        name for name in recipe.functions
        if name.endswith(("_install", "_upgrade", "_remove"))
    ]

def partial_install_files(diff_text: str) -> list[str]:
    """Install-script files whose diff is not the whole file.

    Added files are complete by construction.  A modified file counts as
    complete only when its first hunk starts at line 1 and no hunk was cut
    (``DiffDoc.cut_hunks``); anything else is a fragment, and the hook
    rules must not read it as a whole script.
    """
    try:
        doc = parse_diff_lines(split_lines(diff_text))
    except Exception:
        return []
    cuts = {path for path, *_rest in doc.cut_hunks()}
    partial: list[str] = []
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if file.status == "added":
            continue
        if not file.hunks or file.hunks[0].new_start != 1 or file.path in cuts:
            partial.append(file.path)
    return partial

def install_script_findings(doc) -> list[dict]:
    """C016/C017 over complete ``.install`` scripts (re-filed).

    The file's post-state text is read as a ``RecipeDoc``; every hook body
    is a function.  Findings attribute to the ``.install`` file and its own
    line numbers via the recipe's spans.  A partial file is skipped here:
    :func:`partial_install_files` declares it as a coverage gap instead.
    """
    cuts = {path for path, *_rest in doc.cut_hunks()}
    out: list[dict] = []
    for file in doc.files:
        if not file.path.endswith(".install") or file.status == "removed":
            continue
        if (file.status != "added"
                and (not file.hunks or file.hunks[0].new_start != 1
                     or file.path in cuts)):
            continue
        text = "\n".join(
            line.content for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        )
        origins = [
            (line.file, line.new_lineno or 0, line.side)
            for line in doc.lines
            if line.file == file.path and line.side in ("add", "context")
        ]
        try:
            recipe = parse_recipe(text, origins=origins)
        except Exception:
            continue
        for name in _hook_names(recipe):
            body = recipe.functions.get(name, "")
            if not body:
                continue
            span = recipe.function_spans.get(name)
            match = _HOOK_INTERPRETER_RE.search(body)
            if match:
                out.append(stamp({
                    "rule_id": "C016",
                    "name": "Interpreter Invocation In Install Hook",
                    "severity": "HIGH", "category": "execution",
                    "match": f"{name}() invokes '{match.group(0).strip()}'; "
                             "a hook runs as root at pacman time",
                    "file": span.file if span else file.path,
                    "line": span.line if span else None,
                    "params": {"hook": name, "interpreter": match.group(0).strip()[:40]},
                }))
            for raw_line in split_lines(body):
                for target in _raw_targets(strip_comment(raw_line)):
                    if _user_writable_target(target):
                        out.append(stamp({
                            "rule_id": "C017",
                            "name": "Install Hook Writes To A User-Writable Location",
                            "severity": "HIGH", "category": "persistence",
                            "match": f"{name}() writes to {target.strip()}; "
                                     "the hook runs as root",
                            "file": span.file if span else file.path,
                            "line": span.line if span else None,
                            "params": {"hook": name, "path": target.strip()[:80]},
                        }))
                        break
    return out
