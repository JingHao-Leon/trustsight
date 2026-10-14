"""Extracted from manifests.py: _formats_c."""

from __future__ import annotations
import re
from ...tokenizer import split_lines
from ..manifest_syntax import (
    load_json,
    load_toml,
    load_xml,
    load_yaml,
)
from ._common import Dep, ManifestDoc, _GIT_FIELD_RE, _host, _is_default_registry, _url_source
from ._formats_b import _source_dep

__all__ = ['_CARTFILE_RE', '_CPANFILE_RE', '_GEMSPEC_DEP_RE', '_GRADLE_COORD_RE', '_MIX_DEP_RE', '_OPAM_DEP_RE', '_PODFILE_RE', '_POD_GIT_RE', '_R_DESC_FIELDS', '_R_VERSION_RE', '_bun_lock', '_cabal', '_conan', '_cpanfile', '_deno_json', '_dict_deps', '_dotnet_project', '_fpm_toml', '_gemspec', '_gleam_toml', '_gradle_dsl', '_gradle_libs', '_julia_manifest', '_julia_project', '_localname', '_maven_pom', '_mix_exs', '_mix_lock', '_nuget_config', '_opam', '_packages_config', '_podfile', '_pubspec', '_pubspec_lock', '_r_description', '_renv_lock', '_shard_lock', '_shard_yml', '_swift_package', '_swift_resolved', '_vcpkg', '_xml_text']

def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

def _xml_text(elem, name: str) -> str:
    for child in elem:
        if _localname(child.tag) == name and child.text:
            return child.text.strip()
    return ""

def _maven_pom(text: str) -> ManifestDoc | None:
    root = load_xml(text)
    deps: list[Dep] = []
    for dep in root.iter():
        if _localname(dep.tag) != "dependency":
            continue
        gid = _xml_text(dep, "groupId")
        aid = _xml_text(dep, "artifactId")
        name = f"{gid}:{aid}" if gid else aid
        if name:
            deps.append(Dep(name, _xml_text(dep, "version") or None, "registry", None))
    redirects = []
    for repo in root.iter():
        if _localname(repo.tag) == "repository":
            url = _xml_text(repo, "url")
            if url and "://" in url and not _is_default_registry(url):
                redirects.append(("maven-repository", _host(url) or url))
    return ManifestDoc("", "jvm", tuple(deps), redirects=tuple(redirects))

def _dotnet_project(text: str) -> ManifestDoc | None:
    root = load_xml(text)
    deps: list[Dep] = []
    for ref in root.iter():
        if _localname(ref.tag) != "PackageReference":
            continue
        name = ref.get("Include") or ref.get("Update") or ""
        version = ref.get("Version") or _xml_text(ref, "Version") or None
        if name:
            deps.append(Dep(name, version, "registry", None))
    return ManifestDoc("", "dotnet", tuple(deps))

def _packages_config(text: str) -> ManifestDoc | None:
    root = load_xml(text)
    deps: list[Dep] = []
    for pkg in root.iter():
        if _localname(pkg.tag) == "package" and pkg.get("id"):
            deps.append(Dep(pkg.get("id"), pkg.get("version"), "registry", None))
    return ManifestDoc("", "dotnet", tuple(deps))

def _nuget_config(text: str) -> ManifestDoc | None:
    root = load_xml(text)
    redirects: list[tuple[str, str]] = []
    for add in root.iter():
        if _localname(add.tag) != "add":
            continue
        value = add.get("value") or ""
        if "://" in value and not _is_default_registry(value):
            redirects.append(("nuget-source", _host(value) or value))
    return ManifestDoc("", "dotnet", (), redirects=tuple(redirects))

def _pubspec(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "dart", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for section in ("dependencies", "dev_dependencies", "dependency_overrides"):
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, value in table.items():
            if isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
            elif isinstance(value, dict):
                deps.extend(_source_dep(name, value)
                            or [Dep(name, value.get("version"), "registry", None)])
    return ManifestDoc("", "dart", tuple(deps))

def _shard_yml(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "crystal", unresolved=("not a mapping",))
    deps: list[Dep] = []
    table = data.get("dependencies")
    if isinstance(table, dict):
        for name, value in table.items():
            if isinstance(value, dict):
                if value.get("git"):
                    deps.append(Dep(name, value.get("version"), "git", _host(value["git"])))
                elif value.get("github"):
                    deps.append(Dep(name, value.get("version"), "git", "github.com"))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
            elif isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
    return ManifestDoc("", "crystal", tuple(deps))

def _deno_json(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "npm", unresolved=("not an object",))
    deps: list[Dep] = []
    imports = data.get("imports")
    if isinstance(imports, dict):
        for name, value in imports.items():
            if not isinstance(value, str):
                continue
            if value.startswith(("npm:", "jsr:")):
                deps.append(Dep(name, None, "registry", None))
            else:
                deps.append(Dep(name, None, "git", _host(value)))
    return ManifestDoc("", "npm", tuple(deps))

def _bun_lock(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "npm", unresolved=("not an object",))
    deps: list[Dep] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = key.rsplit("@", 1)[0] if "@" in key else key
            if name.startswith("node_modules/"):
                name = name[len("node_modules/"):]
            resolved = entry.get("resolved", "") or ""
            if isinstance(resolved, str):
                kind, host = _url_source(resolved)
                deps.append(Dep(name, entry.get("version"), kind, host))
    return ManifestDoc("", "npm", tuple(deps))

def _julia_project(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps = [Dep(name, None, "registry", None)
            for name in (data.get("deps") or {})]
    return ManifestDoc("", "julia", tuple(deps))

def _julia_manifest(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    for name, entry in (data.get("deps") or {}).items():
        if isinstance(entry, dict) and entry.get("git-tree-sha1") and not entry.get("path"):
            deps.append(Dep(name, entry.get("version"), "registry", None))
        else:
            deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "julia", tuple(deps))

def _gradle_libs(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    for section in ("libraries", "versions", "bundles", "plugins"):
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, value in table.items():
            if isinstance(value, dict):
                version = value.get("version")
                module = value.get("module") or value.get("group")
                if module:
                    deps.append(Dep(module, version, "registry", None))
                elif section != "versions":
                    deps.append(Dep(name, version, "registry", None))
    return ManifestDoc("", "jvm", tuple(deps))

_GRADLE_COORD_RE = re.compile(r"[\"']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\"']+)[\"']")

def _gradle_dsl(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in _GRADLE_COORD_RE.finditer(text):
        deps.append(Dep(f"{match.group(1)}:{match.group(2)}",
                        match.group(3), "registry", None))
    return ManifestDoc("", "jvm", tuple(deps))

def _vcpkg(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "cpp", unresolved=("not an object",))
    deps: list[Dep] = []
    for entry in data.get("dependencies", ()) or ():
        if isinstance(entry, str):
            deps.append(Dep(entry, None, "registry", None))
        elif isinstance(entry, dict) and entry.get("name"):
            deps.append(Dep(entry["name"], None, "registry", None))
    redirects = []
    reg_cfg = data.get("vcpkg-configuration")
    if isinstance(reg_cfg, dict):
        for reg in reg_cfg.get("registries", ()) or ():
            if isinstance(reg, dict) and reg.get("repository"):
                url = reg["repository"]
                if "://" in url and not _is_default_registry(url):
                    redirects.append(("vcpkg-registry", _host(url) or url))
    return ManifestDoc("", "cpp", tuple(deps), redirects=tuple(redirects))

def _cabal(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    collecting = False
    for line in split_lines(text):
        stripped = line.strip()
        if stripped.lower().startswith("build-depends:"):
            collecting = True
            stripped = stripped.split(":", 1)[1]
        elif collecting and not line[:1].isspace():
            collecting = False
            continue
        if not collecting:
            continue
        for token in stripped.split(","):
            name = token.strip().split(" ")[0].split(">")[0].split("<")[0].split("=")[0]
            name = name.strip()
            if name and name[0].isalpha():
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "haskell", tuple(deps))

_OPAM_DEP_RE = re.compile(r"[\"']([A-Za-z0-9_.+-]+)[\"']")

def _opam(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    collecting = False
    for line in split_lines(text):
        if re.match(r"^\s*depends\s*:", line):
            collecting = True
        elif collecting and re.match(r"^\s*[a-z-]+\s*:", line):
            collecting = False
        if collecting:
            for name in _OPAM_DEP_RE.findall(line.split(":", 1)[-1]):
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "ocaml", tuple(deps))

_MIX_DEP_RE = re.compile(
    r"\{\s*:([A-Za-z0-9_]+)\s*,([^}]*)\}")

def _mix_exs(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for name, rest in _MIX_DEP_RE.findall(text):
        url = _GIT_FIELD_RE.search(rest)
        if url:
            deps.append(Dep(name, None, "git", _host(url.group("dq") or "")))
        else:
            deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "elixir", tuple(deps))

def _mix_lock(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in re.finditer(r":([a-z0-9_]+),\s*:([a-z0-9_]+),\s*\"([^\"]+)\"", text):
        deps.append(Dep(match.group(2), match.group(3), "registry", None))
    return ManifestDoc("", "elixir", tuple(deps))

def _conan(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    collecting = False
    for line in split_lines(text):
        stripped = line.strip()
        if stripped.startswith("["):
            collecting = stripped.lower() == "[requires]"
            continue
        if collecting and stripped and not stripped.startswith("#"):
            name = stripped.split("/", 1)[0].strip()
            if name:
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "cpp", tuple(deps))

_R_DESC_FIELDS = ("Depends", "Imports", "Suggests", "LinkingTo", "Enhances")

_R_VERSION_RE = re.compile(r"\(([^)]*)\)")

def _r_description(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    collecting = False
    for line in split_lines(text):
        if not line.strip():
            collecting = False
            continue
        if line[:1].isspace() and collecting:
            body = line.strip()
        elif not line[:1].isspace():
            key, _, body = line.partition(":")
            collecting = key.strip() in _R_DESC_FIELDS
            if not collecting:
                continue
        else:
            continue
        for token in body.split(","):
            name = token.strip().split(" ")[0].split("(")[0].strip()
            if name and name not in ("R",):
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "r", tuple(deps))

def _renv_lock(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "r", unresolved=("not an object",))
    deps: list[Dep] = []
    packages = data.get("Packages")
    if isinstance(packages, dict):
        for name, entry in packages.items():
            if isinstance(entry, dict):
                repo = entry.get("Repository") or ""
                source = str(entry.get("Source") or "")
                if repo and "://" in str(repo) and not _is_default_registry(str(repo)):
                    deps.append(Dep(name, entry.get("Version"), "git", _host(str(repo))))
                elif "github" in source.lower() or "git" in source.lower():
                    deps.append(Dep(name, entry.get("Version"), "git", None))
                else:
                    deps.append(Dep(name, entry.get("Version"), "registry", None))
    return ManifestDoc("", "r", tuple(deps))

_CPANFILE_RE = re.compile(
    r"^\s*(?:requires|recommends|suggests|test_requires|configure_requires"
    r"|build_requires|runtime_requires)\s+[\"']([A-Za-z0-9_:]+)[\"']",
    re.MULTILINE)

def _cpanfile(text: str) -> ManifestDoc | None:
    deps = [Dep(name, None, "registry", None)
            for name in _CPANFILE_RE.findall(text)]
    return ManifestDoc("", "perl", tuple(deps))

def _dict_deps(text: str, fmt: str, sections=("dependencies",)) -> ManifestDoc | None:
    """A TOML manifest whose deps live in a ``name = value`` table."""
    data = load_toml(text)
    deps: list[Dep] = []
    for section in sections:
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, value in table.items():
            if isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
            elif isinstance(value, dict):
                deps.extend(_source_dep(name, value)
                            or [Dep(name, value.get("version"), "registry", None)])
    return ManifestDoc("", fmt, tuple(deps))

def _fpm_toml(text: str) -> ManifestDoc | None:
    return _dict_deps(text, "fortran",
                      ("dependencies", "dev-dependencies", "test"))

def _gleam_toml(text: str) -> ManifestDoc | None:
    return _dict_deps(text, "gleam",
                      ("dependencies", "dev-dependencies"))

def _pubspec_lock(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "dart", unresolved=("not a mapping",))
    deps: list[Dep] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for name, entry in packages.items():
            if not isinstance(entry, dict):
                continue
            source = str(entry.get("source") or "")
            url = entry.get("url")
            if "git" in source:
                deps.append(Dep(name, entry.get("version"), "git",
                                _host(str(url)) if url else "github.com"))
            elif "path" in source:
                deps.append(Dep(name, entry.get("version"), "path", None))
            else:
                deps.append(Dep(name, entry.get("version"), "registry", None))
    return ManifestDoc("", "dart", tuple(deps))

def _shard_lock(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "crystal", unresolved=("not a mapping",))
    deps: list[Dep] = []
    shards = data.get("shards")
    if isinstance(shards, dict):
        for name, entry in shards.items():
            if isinstance(entry, dict):
                if entry.get("git"):
                    deps.append(Dep(name, entry.get("version"), "git", _host(entry["git"])))
                else:
                    deps.append(Dep(name, entry.get("version"), "registry", None))
    return ManifestDoc("", "crystal", tuple(deps))

_GEMSPEC_DEP_RE = re.compile(
    r"add(?:_runtime|_development)?_dependency\s*\(?\s*[\"']([^\"']+)[\"']"
    r"(?:\s*,\s*[\"']([^\"']+)[\"'])?")

def _gemspec(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _GEMSPEC_DEP_RE.finditer(text)]
    return ManifestDoc("", "gem", tuple(deps))

_CARTFILE_RE = re.compile(r"git\s+[\"']([^\"']+)[\"']")

_PODFILE_RE = re.compile(
    r"pod\s+[\"']([^\"']+)[\"'](?P<rest>[^\n]*)")

_POD_GIT_RE = re.compile(r":git\s*=>\s*[\"']([^\"']+)[\"']")

def _podfile(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in _PODFILE_RE.finditer(text):
        rest = match.group("rest")
        git = _POD_GIT_RE.search(rest)
        if git:
            deps.append(Dep(match.group(1), None, "git", _host(git.group(1))))
        else:
            deps.append(Dep(match.group(1), None, "registry", None))
    redirects = []
    for match in re.finditer(r"source\s+[\"']([^\"']+)[\"']", text):
        url = match.group(1)
        if "://" in url and "cocoapods.org" not in url:
            redirects.append(("pod-source", _host(url) or url))
    return ManifestDoc("", "swift", tuple(deps), redirects=tuple(redirects))

def _swift_resolved(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "swift", unresolved=("not an object",))
    deps: list[Dep] = []
    for pin in data.get("pins", ()) or ():
        if not isinstance(pin, dict):
            continue
        name = pin.get("identity") or pin.get("package") or ""
        location = pin.get("location") or ""
        if location:
            deps.append(Dep(name, None, "git", _host(str(location))))
    return ManifestDoc("", "swift", tuple(deps))

def _swift_package(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in re.finditer(r"\.package\s*\(\s*(?:name:[^,]+,\s*)?url:\s*\"([^\"]+)\"", text):
        url = match.group(1)
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        deps.append(Dep(name, None, "git", _host(url)))
    return ManifestDoc("", "swift", tuple(deps))
