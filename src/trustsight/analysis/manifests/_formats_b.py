"""Extracted from manifests.py: _formats_b."""

from __future__ import annotations
import re
from ...tokenizer import split_lines
from ..manifest_syntax import (
    load_ini,
    load_toml,
    load_yaml,
)
from ._common import Dep, ManifestDoc, _host, _is_default_registry, _pep508, _url_source

__all__ = ['_NOX_INSTALL_RE', '_SETUP_EXTRAS_RE', '_SETUP_REQUIRES_RE', '_SETUP_STR_RE', '_add_pixi', '_as_list', '_conda_dep', '_conda_env', '_conda_meta', '_ini_requirements', '_noxfile', '_pip_config', '_pixi', '_pixi_channels', '_pixi_tables', '_pylock', '_pypirc', '_setup_cfg', '_setup_py', '_source_dep', '_tox_ini', '_uv_toml']

def _pylock(text: str) -> ManifestDoc | None:
    """PEP 751 ``pylock.toml``: ``[[packages]]`` with a source table."""
    data = load_toml(text)
    deps = []
    for pkg in data.get("packages", ()) or ():
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name", ""), pkg.get("version")
        vcs = pkg.get("vcs")
        if isinstance(vcs, dict) and vcs.get("url"):
            deps.append(Dep(name, version, "git", _host(vcs["url"])))
            continue
        if isinstance(pkg.get("directory"), dict):
            deps.append(Dep(name, version, "path", None))
            continue
        kind, host = "registry", None
        for key in ("archive", "sdist"):
            blob = pkg.get(key)
            if isinstance(blob, dict) and blob.get("url"):
                kind, host = _url_source(blob["url"])
                break
        if host is None and isinstance(pkg.get("wheels"), list):
            for wheel in pkg["wheels"]:
                if isinstance(wheel, dict) and wheel.get("url"):
                    kind, host = _url_source(wheel["url"])
                    if host:
                        break
        if host is None:
            index = pkg.get("index")
            if isinstance(index, str) and not _is_default_registry(index):
                host = _host(index)
        deps.append(Dep(name, version, kind, host))
    return ManifestDoc("", "pip", tuple(deps))

def _uv_toml(text: str) -> ManifestDoc | None:
    """uv's ``uv.toml``: resolver redirects and source overrides."""
    data = load_toml(text)
    deps: list[Dep] = []
    redirects: list[tuple[str, str]] = []
    for index in data.get("index", ()) or ():
        if isinstance(index, dict) and index.get("url"):
            if not _is_default_registry(str(index["url"])):
                redirects.append(("uv-index", _host(index["url"]) or index["url"]))
    pip = data.get("pip")
    if isinstance(pip, dict):
        for key in ("index-url", "extra-index-url"):
            value = pip.get(key)
            if isinstance(value, str) and not _is_default_registry(value):
                redirects.append(("uv-pip-index", _host(value) or value))
        for value in _as_list(pip.get("find-links")):
            if isinstance(value, str) and "://" in value and not _is_default_registry(value):
                redirects.append(("uv-pip-find-links", _host(value) or value))
    for name, src in (data.get("sources") or {}).items():
        deps.extend(_source_dep(name, src))
    return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))

def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]

def _source_dep(name: str, src) -> list[Dep]:
    """One uv/pixi source table (git/url/path/index/workspace) as a dep."""
    if not isinstance(src, dict):
        return []
    if src.get("git"):
        return [Dep(name, src.get("version"), "git", _host(src["git"]))]
    if src.get("url"):
        kind, host = _url_source(src["url"])
        return [Dep(name, src.get("version"), kind, host)]
    if any(src.get(k) for k in ("path", "editable", "workspace", "directory")):
        return [Dep(name, src.get("version"), "path", None)]
    return [Dep(name, src.get("version"), "registry", None)]

def _conda_dep(spec: str) -> Dep | None:
    """A conda spec ``name[=version][=build]`` as a registry dep."""
    text = str(spec).strip().strip("\"'")
    if not text or text.startswith(("#", "!")):
        return None
    name = re.split(r"[=<>!~\s]", text, maxsplit=1)[0].strip()
    if not name:
        return None
    return Dep(name, None, "registry", None)

def _conda_env(text: str) -> ManifestDoc | None:
    """``environment.yml``: the conda dependency list plus its ``pip:`` sublist."""
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "conda", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for entry in data.get("dependencies", ()) or ():
        if isinstance(entry, str):
            dep = _conda_dep(entry)
            if dep:
                deps.append(dep)
        elif isinstance(entry, dict):
            for raw in entry.get("pip", ()) or ():
                dep = _pep508(str(raw))
                if dep and dep.name:
                    deps.append(dep)
    redirects = []
    for channel in _as_list(data.get("channels")):
        if isinstance(channel, str) and "://" in channel \
                and not _is_default_registry(channel):
            redirects.append(("conda-channel", _host(channel) or channel))
    return ManifestDoc("", "conda", tuple(deps), redirects=tuple(redirects))

def _conda_meta(text: str) -> ManifestDoc | None:
    """conda-build ``meta.yaml``: ``requirements.build/host/run``."""
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "conda", unresolved=("not a mapping",))
    deps: list[Dep] = []
    req = data.get("requirements")
    if isinstance(req, dict):
        for section in ("build", "host", "run", "run_constrained"):
            for spec in req.get(section, ()) or ():
                dep = _conda_dep(spec)
                if dep:
                    deps.append(dep)
    return ManifestDoc("", "conda", tuple(deps))

def _pixi_tables(root: dict):
    """Yield the dependency tables a pixi manifest (or ``[tool.pixi]``) holds."""
    if not isinstance(root, dict):
        return
    for key in ("dependencies", "pypi-dependencies", "host-dependencies",
                "build-dependencies", "run-dependencies",
                "run-constraints", "constraints"):
        yield root.get(key)
    for group in ("feature", "target", "package"):
        section = root.get(group)
        if isinstance(section, dict):
            for entry in section.values():
                if not isinstance(entry, dict):
                    continue
                for key in ("dependencies", "pypi-dependencies", "host-dependencies",
                            "build-dependencies", "run-dependencies",
                            "run-constraints", "constraints"):
                    yield entry.get(key)

def _pixi_channels(root: dict):
    workspace = root.get("workspace") if isinstance(root, dict) else None
    if isinstance(workspace, dict):
        yield from _as_list(workspace.get("channels"))

def _add_pixi(data_root: dict, deps: list[Dep], redirects: list[tuple[str, str]]):
    for table in _pixi_tables(data_root):
        if not isinstance(table, dict):
            continue
        for name, value in table.items():
            if isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
            elif isinstance(value, dict):
                deps.extend(_source_dep(name, value))
    for channel in _pixi_channels(data_root):
        if isinstance(channel, str) and "://" in channel \
                and not _is_default_registry(channel):
            redirects.append(("pixi-channel", _host(channel) or channel))

def _pixi(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    redirects: list[tuple[str, str]] = []
    _add_pixi(data, deps, redirects)
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("pixi"), dict):
        _add_pixi(tool["pixi"], deps, redirects)
    return ManifestDoc("", "conda", tuple(deps), redirects=tuple(redirects))

def _ini_requirements(value: str):
    for raw in split_lines(value):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        line = line.split(" #", 1)[0].strip()
        dep = _pep508(line)
        if dep and dep.name:
            yield dep

def _setup_cfg(text: str) -> ManifestDoc | None:
    parser = load_ini(text)
    deps: list[Dep] = []
    if parser.has_section("options"):
        for key in ("install_requires", "setup_requires", "tests_require"):
            if parser.has_option("options", key):
                deps.extend(_ini_requirements(parser.get("options", key)))
    if parser.has_section("options.extras_require"):
        for _extra, value in parser.items("options.extras_require"):
            deps.extend(_ini_requirements(value))
    return ManifestDoc("", "pip", tuple(deps))

def _tox_ini(text: str) -> ManifestDoc | None:
    parser = load_ini(text)
    deps: list[Dep] = []
    for section in parser.sections():
        if (section == "testenv" or section.startswith("testenv:")) \
                and parser.has_option(section, "deps"):
            deps.extend(_ini_requirements(parser.get(section, "deps")))
    return ManifestDoc("", "pip", tuple(deps))

def _pip_config(text: str) -> ManifestDoc | None:
    parser = load_ini(text)
    redirects: list[tuple[str, str]] = []
    for section in parser.sections():
        for key in ("index-url", "extra-index-url"):
            if parser.has_option(section, key):
                value = parser.get(section, key).strip()
                if value and not _is_default_registry(value):
                    redirects.append(("pip-index-url", _host(value) or value))
        if parser.has_option(section, "find-links"):
            for value in re.split(r"[\s,]+", parser.get(section, "find-links")):
                if "://" in value and not _is_default_registry(value):
                    redirects.append(("pip-find-links", _host(value) or value))
        if parser.has_option(section, "trusted-host"):
            host = parser.get(section, "trusted-host").strip()
            if host:
                redirects.append(("pip-trusted-host", host))
    return ManifestDoc("", "pip", (), redirects=tuple(redirects))

def _pypirc(text: str) -> ManifestDoc | None:
    parser = load_ini(text)
    redirects: list[tuple[str, str]] = []
    for section in parser.sections():
        if section == "distutils":
            continue
        if parser.has_option(section, "repository"):
            value = parser.get(section, "repository").strip()
            if value and not _is_default_registry(value):
                redirects.append(("pypirc-repository", _host(value) or value))
    return ManifestDoc("", "pip", (), redirects=tuple(redirects))

_SETUP_REQUIRES_RE = re.compile(
    r"\b(?:install_requires|setup_requires|tests_require)\s*=\s*\[(.*?)\]",
    re.DOTALL)

_SETUP_EXTRAS_RE = re.compile(r"\bextras_require\s*=\s*\{(.*?)\}", re.DOTALL)

_SETUP_STR_RE = re.compile(r"[\"']([^\"']+)[\"']")

def _setup_py(text: str) -> ManifestDoc | None:
    """Legacy ``setup.py``: extract requirement string literals only."""
    deps: list[Dep] = []
    for match in _SETUP_REQUIRES_RE.finditer(text):
        for raw in _SETUP_STR_RE.findall(match.group(1)):
            dep = _pep508(raw)
            if dep and dep.name:
                deps.append(dep)
    for match in _SETUP_EXTRAS_RE.finditer(text):
        for raw in _SETUP_STR_RE.findall(match.group(1)):
            dep = _pep508(raw)
            if dep and dep.name:
                deps.append(dep)
    return ManifestDoc("", "pip", tuple(deps))

_NOX_INSTALL_RE = re.compile(r"\.install(?:_requires)?\s*\(([^)]*)\)")

def _noxfile(text: str) -> ManifestDoc | None:
    """nox ``noxfile.py``: the string literals passed to ``session.install``."""
    deps: list[Dep] = []
    for match in _NOX_INSTALL_RE.finditer(text):
        for raw in _SETUP_STR_RE.findall(match.group(1)):
            dep = _pep508(raw)
            if dep and dep.name:
                deps.append(dep)
    return ManifestDoc("", "pip", tuple(deps))
