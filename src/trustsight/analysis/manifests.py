"""U-series: upstream dependency manifests committed in the AUR repository.

TrustSight never fetches what a package declares and never extracts archives
(A2, A8), so an upstream *archive* is a sealed container.  But the manifests
that ship beside a recipe (``Cargo.toml``, ``package.json``,
``requirements.txt``, ``go.mod``, ...) are committed to the repository, which
means the existing tree walk and diff already see them.  This module turns
those bytes into one :class:`ManifestDoc` per file, mirroring the
``RecipeDoc`` contract: parse once, project everywhere, refuse rather than
guess.

It is a pure read: no fetch, no extraction, no new walker.  Discovery is the
existing tree walk and diff file list, filtered by a filename table that
lives in ``patterns.toml`` (configuration, not a code constant).
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..buckets import canonical_host
from ..tokenizer import split_lines
from .manifest_syntax import (
    ManifestSyntaxError,
    load_ini,
    load_json,
    load_toml,
    load_xml,
    load_yaml,
)

__all__ = [
    "Dep",
    "ManifestDoc",
    "manifest_format",
    "manifest_filenames",
    "parse_manifest",
    "upstream_redirect_signals",
    "upstream_source_deps",
    "upstream_source_hosts",
    "MAX_MANIFEST_BYTES",
]

#: The existing per-file tree cap (``pipeline._collect_tree_files``); reused
#: here so a hostile manifest is refused on the same bound, not a new one.
MAX_MANIFEST_BYTES = 512 * 1024

#: Fallback table when the config layer is unavailable (tests, isolated
#: imports).  The canonical copy lives in ``config.DEFAULT_MANIFEST_FILENAMES``
#: and is written to ``patterns.toml``; this mirror keeps the parsers usable
#: without a config directory.  Entries are ``"format::name"``, where a name
#: with a ``/`` matches as a path suffix and a bare name as a basename.
_FALLBACK_FILENAMES: tuple[str, ...] = (
    "cargo::Cargo.toml",
    "cargo::Cargo.lock",
    "cargo::cargo/config.toml",
    "cargo::.cargo/config.toml",
    "cargo::cargo/config",
    "cargo::.cargo/config",
    "npm::package.json",
    "npm::package-lock.json",
    "npm::npm-shrinkwrap.json",
    "npm::yarn.lock",
    "npm::pnpm-lock.yaml",
    "npm::.npmrc",
    "npm::.yarnrc.yml",
    "pip::pyproject.toml",
    "pip::requirements.txt",
    "pip::requirements*.txt",
    "pip::requirements/*.txt",
    "pip::*-requirements.txt",
    "pip::requirements*.in",
    "pip::constraints.txt",
    "pip::constraints*.txt",
    "pip::Pipfile",
    "pip::Pipfile.lock",
    "pip::poetry.lock",
    "pip::uv.lock",
    "pip::uv.toml",
    "pip::pdm.lock",
    "pip::pylock.toml",
    "pip::pylock.*.toml",
    "pip::setup.py",
    "pip::setup.cfg",
    "pip::tox.ini",
    "pip::noxfile.py",
    "pip::pip.conf",
    "pip::pip.ini",
    "pip::.pip/pip.conf",
    "pip::.config/pip/pip.conf",
    "pip::.pypirc",
    "conda::environment.yml",
    "conda::environment.yaml",
    "conda::meta.yaml",
    "conda::pixi.toml",
    "conda::pixi.lock",
    "conda::conda-lock.yml",
    "conda::*.conda-lock.yml",
    "go::go.mod",
    "go::go.sum",
    "go::go.work",
    "go::go.work.sum",
    "gem::Gemfile",
    "gem::Gemfile.lock",
    "gem::*.gemspec",
    "composer::composer.json",
    "composer::composer.lock",
    "npm::deno.json",
    "npm::deno.jsonc",
    "npm::bun.lock",
    "jvm::pom.xml",
    "jvm::build.gradle",
    "jvm::build.gradle.kts",
    "jvm::settings.gradle",
    "jvm::settings.gradle.kts",
    "jvm::gradle/libs.versions.toml",
    "dotnet::*.csproj",
    "dotnet::*.fsproj",
    "dotnet::*.vbproj",
    "dotnet::packages.config",
    "dotnet::NuGet.config",
    "dotnet::Directory.Packages.props",
    "dart::pubspec.yaml",
    "dart::pubspec.lock",
    "crystal::shard.yml",
    "crystal::shard.lock",
    "julia::Project.toml",
    "julia::Manifest.toml",
    "cpp::vcpkg.json",
    "cpp::conanfile.txt",
    "haskell::*.cabal",
    "ocaml::*.opam",
    "elixir::mix.exs",
    "elixir::mix.lock",
    "r::DESCRIPTION",
    "r::renv.lock",
    "perl::cpanfile",
    "fortran::fpm.toml",
    "gleam::gleam.toml",
    "swift::Package.resolved",
    "swift::Package.swift",
    "swift::Podfile",
    "swift::Cartfile",
    "swift::Cartfile.resolved",
    "zig::build.zig.zon",
    "d::dub.json",
    "nim::*.nimble",
    "lua::*.rockspec",
    "clojure::deps.edn",
    "clojure::project.clj",
    "ocaml::dune-project",
    "elixir::rebar.config",
    "elixir::rebar.lock",
    "haskell::cabal.project",
    "haskell::cabal.project.freeze",
    "haskell::stack.yaml",
    "haskell::stack.yaml.lock",
    "haskell::package.yaml",
    "cpp::CMakeLists.txt",
    "cpp::meson.build",
    "bazel::MODULE.bazel",
    "perl::META.json",
    "perl::META.yml",
)


@dataclass(frozen=True)
class Dep:
    """One dependency line, normalized across formats."""

    name: str
    constraint: str | None
    source_kind: str  # "registry" | "git" | "path" | "unknown"
    remote: str | None  # canonical host of a git or non-default-registry source

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "constraint": self.constraint,
            "source_kind": self.source_kind,
            "remote": self.remote,
        }


@dataclass
class ManifestDoc:
    """A parsed manifest: its dependencies, refusals, and redirect signals."""

    path: str
    format: str
    dependencies: tuple[Dep, ...] = ()
    #: Named refusals ("malformed json", "over the byte cap", ...).  A refused
    #: manifest is a boundary the report names, never a silent skip (B2).
    unresolved: tuple[str, ...] = ()
    #: U004 redirect signals: (kind, value) for a resolver being pointed
    #: somewhere other than the default registry.
    redirects: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "unresolved": list(self.unresolved),
            "redirects": [list(r) for r in self.redirects],
        }


# ---------------------------------------------------------------------------
# Discovery: the filename table (config-driven)
# ---------------------------------------------------------------------------


def manifest_filenames() -> tuple[str, ...]:
    """The configured ``format::name`` table, from patterns.toml."""
    try:
        from ..config import DEFAULT_MANIFEST_FILENAMES, load_patterns

        patterns = load_patterns().get("patterns", {})
        table = patterns.get("manifest_filenames")
        if table:
            return tuple(str(x) for x in table)
        return tuple(DEFAULT_MANIFEST_FILENAMES)
    except Exception:  # noqa: BLE001 - config is an optimization here
        return _FALLBACK_FILENAMES


def _table() -> list[tuple[str, str]]:
    """``(name-glob, format)`` in table order, normalized (lowercased)."""
    out: list[tuple[str, str]] = []
    for entry in manifest_filenames():
        fmt, _, name = str(entry).partition("::")
        if name:
            out.append((name.lower(), fmt))
    return out


def _glob_rank(name: str) -> tuple[int, int]:
    """Sort key: exact before glob, then longer (more specific) first."""
    return (name.count("*") + name.count("?"), -len(name))


def _matches(lowered: str, base: str, name: str) -> bool:
    """Does the manifest name-glob *name* own path *lowered*?"""
    if "/" in name:
        if lowered == name or lowered.endswith("/" + name):
            return True
        return (fnmatch.fnmatchcase(lowered, name)
                or fnmatch.fnmatchcase(lowered, "*/" + name))
    return base == name or fnmatch.fnmatchcase(base, name)


def manifest_format(path: str) -> str | None:
    """The format family owning *path*, or None when it is not a manifest.

    Names are globs (``requirements*.txt``, ``*.csproj``).  The most
    specific match wins - an exact ``requirements.txt`` over
    ``requirements*.txt`` - so a glob added for one tool cannot silently
    capture another tool's exact file.
    """
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    best_fmt: str | None = None
    best_key: tuple[int, int] | None = None
    for name, fmt in _table():
        if not _matches(lowered, base, name):
            continue
        key = _glob_rank(name)
        if best_key is None or key < best_key:
            best_key, best_fmt = key, fmt
    return best_fmt


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _host(url: str) -> str | None:
    """Canonical host of a dependency address, git or plain URL.

    Handles a scheme, `git+`/scp forms, a protocol-relative `//host/...`,
    and a bare dotted `host.tld/path` - the spellings an attacker uses to
    hide the host from a scheme-only reader.
    """
    if not url:
        return None
    value = url.strip().strip("\"'")
    for prefix in ("git+", "hg+", "svn+", "bzr+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value.startswith("git@"):
        host = value[len("git@"):].split(":", 1)[0].split("/", 1)[0]
        return canonical_host(host) or None
    if value.startswith("//"):
        value = "https:" + value
    if "://" in value:
        return canonical_host(urlsplit(value).netloc) or None
    # A bare `host.tld/path` (no scheme).  A bare `user/repo` shorthand has
    # no dot in its first segment and is not a host.
    first = value.split("/", 1)[0]
    if "." in first and " " not in first and "@" not in first:
        return canonical_host(first) or None
    return None


#: Registries whose address is the default for its ecosystem, so a
#: dependency that names one has not extended the fetch surface.
_DEFAULT_REGISTRY_FRAGMENTS = (
    "crates.io", "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org", "pythonhosted.org",
    "rubygems.org", "packagist.org",
    "repo.maven.apache.org", "repo1.maven.org", "maven.org",
    "nuget.org", "jsr.io", "deno.land", "pub.dev", "hex.pm",
    "hackage.haskell.org", "opam.ocaml.org", "crates.io",
    "proxy.golang.org", "conda.anaconda.org", "anaconda.org",
)


def _is_default_registry(url: str) -> bool:
    lowered = (url or "").lower()
    return any(fragment in lowered for fragment in _DEFAULT_REGISTRY_FRAGMENTS)


def _registry_host(url: str) -> str | None:
    """The host of a registry address, or None when it is a default registry."""
    if not url:
        return None
    value = url
    for prefix in ("registry+", "sparse+"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if _is_default_registry(value):
        return None
    return _host(value)


def _url_source(url: str) -> tuple[str, str | None]:
    """``(source_kind, host)`` for a lockfile resolved/from URL.

    A tarball or registry URL on the default host is not a remote: naming it
    one would flag every lockfile's first commit.  A git URL, or any URL on a
    host the ecosystem does not default to, is.
    """
    if not url:
        return "registry", None
    low = url.lower()
    if low.startswith(("git+", "git://", "git@")) or "git+" in low:
        return "git", _host(url)
    host = _host(url)
    if host and not _is_default_registry(url):
        return "registry", host
    return "registry", None


# ---------------------------------------------------------------------------
# Section-agnostic source scan
#
# A real diff carries three lines of context, so a hunk that adds a
# dependency frequently omits the `[dependencies]` header or the opening `{`
# it lives under.  Parsing the hunk as a whole then loses the change (a bare
# `key = { git = ... }` is not a dependency table; a JSON fragment is not
# JSON), and a structured-only read reports nothing while the build fetches
# from a host the recipe never declared.  The scan below reads the raw
# spelling of a source wherever it appears, so the scored signal survives a
# partial hunk.  It is deliberately narrow: only git/registry spellings, not
# a bare `homepage = "https://..."`.
# ---------------------------------------------------------------------------

_FORGE_HOSTS = {
    "github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org",
}

_GIT_URL_RE = re.compile(
    r"\bgit\+[A-Za-z0-9]+://[^\s\"'<>()]+"
    r"|\bgit://[^\s\"'<>()]+"
    r"|\bgit@[A-Za-z0-9._-]+"
    r"|\b(?:github|gitlab|bitbucket):[^\s\"'<>()]+",
    re.IGNORECASE,
)
_GIT_FIELD_RE = re.compile(
    r"\bgit\s*[:=]\s*(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<raw>[^\s,}\]]+))"
)
_REGISTRY_FIELD_RE = re.compile(
    r"\b(?:source|registry)\s*[:=]\s*\"?"
    r"(?P<val>(?:(?:registry|sparse|git)\+)?(?:https?|ssh|git)://[^\s\"',}\]]+)"
)
_LEADING_KEY_RE = re.compile(r"^\s*[\"']?(?P<name>[A-Za-z0-9_.@+/-]+)[\"']?\s*[:=]")
# Anchored on the `@`, which is rare, rather than on the name class, which
# matches almost every character: a leading class makes the scan O(n^2) on a
# long line the safety gate rejects.
_PEP508_URL_RE = re.compile(r"@\s*(?:git\+|git://|https?://|github:|gitlab:|bitbucket:)")


def _pep508_name(line: str) -> str:
    """The requirement name to the left of a PEP 508 ``@ url``, if any."""
    at = _PEP508_URL_RE.search(line)
    if not at:
        return ""
    head = line[:at.start()].strip().strip("\"'").rstrip("@").strip()
    if not head:
        return ""
    token = head.split(",")[0].strip().split("[", 1)[0].strip()
    return token if re.fullmatch(r"[A-Za-z0-9_.-]+", token) else ""


def _live_text(text: str) -> str:
    """*text* without its comment lines: a commented source fetches nothing."""
    return "\n".join(
        line for line in split_lines(text)
        if not line.lstrip().startswith(("#", "//"))
    )


def upstream_source_hosts(text: str) -> set[str]:
    """Hosts named by a git or non-default-registry spelling anywhere in *text*."""
    hosts: set[str] = set()
    text = _live_text(text)
    for m in _GIT_URL_RE.finditer(text):
        token = m.group(0)
        low = token.lower()
        for forge, host in _FORGE_HOSTS.items():
            if low.startswith(forge + ":"):
                hosts.add(host)
                break
        else:
            found = _host(token)
            if found:
                hosts.add(found)
    for m in _GIT_FIELD_RE.finditer(text):
        found = _host(m.group("dq") or m.group("sq") or m.group("raw") or "")
        if found:
            hosts.add(found)
    for m in _REGISTRY_FIELD_RE.finditer(text):
        found = _registry_host(m.group("val"))
        if found:
            hosts.add(found)
    return hosts


def upstream_source_deps(text: str) -> list[Dep]:
    """Best-effort dep names for the source spellings *text* carries."""
    deps: list[Dep] = []
    for line in split_lines(text):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")):
            continue
        hosts = upstream_source_hosts(line)
        if not hosts:
            continue
        m = _LEADING_KEY_RE.match(line)
        name = m.group("name") if m else _pep508_name(line)
        for host in sorted(hosts):
            deps.append(Dep(name, None, "git", host))
    return deps


_CARGO_REPLACE_RE = re.compile(r"\breplace-with\s*[:=]\s*\"(?P<name>[^\"]+)\"")
_REGISTRY_KEY_RE = re.compile(
    r"\bregistry\s*[:=]\s*\"?"
    r"(?P<url>(?:(?:registry|sparse|git)\+)?[^\s\"',}\]]+)"
)


def upstream_redirect_signals(text: str) -> set[tuple[str, str]]:
    """Resolver redirects readable without their enclosing section."""
    out: set[tuple[str, str]] = set()
    text = _live_text(text)
    for m in _CARGO_REPLACE_RE.finditer(text):
        out.add(("cargo-replace-with", m.group("name")))
    for m in _REGISTRY_KEY_RE.finditer(text):
        url = m.group("url")
        if _is_default_registry(url):
            continue
        out.add(("registry-override", _host(url) or url))
    return out


def _pep508(raw: str) -> Dep | None:
    """Parse one PEP 508 requirement string into a dep (best effort)."""
    text = raw.strip().strip("\"'")
    if not text or text.startswith("-") or text.startswith("#"):
        return None
    # `name @ url` (PEP 508 allows whitespace around `@` to be omitted).
    m = re.match(r"^(?P<name>[A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*@\s*(?P<url>\S+)", text)
    if m:
        name, url = m.group("name"), m.group("url")
        if url.lower().startswith("file:"):
            return Dep(name, None, "path", None)
        kind, remote = ("git", _host(url)) if "://" in url else ("unknown", None)
        return Dep(name, None, kind, remote)
    # `git+url#egg=name`
    if text.startswith(("git+", "hg+", "svn+", "bzr+")):
        remote = _host(text)
        name = ""
        m = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", text)
        if m:
            name = m.group(1)
        return Dep(name, None, "git", remote)
    if "://" in text:  # direct URL without a name
        return Dep("", None, "git", _host(text))
    m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", text)
    if not m:
        return None
    name, rest = m.group(1), m.group(2).strip()
    return Dep(name, rest or None, "registry", None)


# ---------------------------------------------------------------------------
# Format parsers
# ---------------------------------------------------------------------------


def _cargo_toml(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    tables = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        if isinstance(data.get(key), dict):
            tables.append(data[key])
    ws = data.get("workspace")
    if isinstance(ws, dict) and isinstance(ws.get("dependencies"), dict):
        tables.append(ws["dependencies"])
    # [patch.crates-io] / [replace] can point a registry dep at a git source.
    for key in ("patch", "replace"):
        section = data.get(key)
        if isinstance(section, dict):
            for sub in section.values():
                if isinstance(sub, dict):
                    tables.append(sub)
    for target in (data.get("target") or {}).values():
        if not isinstance(target, dict):
            continue
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            if isinstance(target.get(key), dict):
                tables.append(target[key])
    for table in tables:
        for name, value in table.items():
            if isinstance(value, str):
                deps.append(Dep(name, value or None, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    constraint = (value.get("tag") or value.get("branch")
                                  or value.get("rev") or value.get("version"))
                    deps.append(Dep(name, constraint, "git", _host(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                elif value.get("registry"):
                    # A per-dep custom registry (e.g. sparse+https://host/...)
                    deps.append(Dep(name, value.get("version"), "registry",
                                    _registry_host(value["registry"])))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    return ManifestDoc("", "cargo", tuple(deps))


def _cargo_lock(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "")
        version = pkg.get("version")
        source = pkg.get("source", "") or ""
        if source.startswith("git+"):
            deps.append(Dep(name, version, "git", _host(source)))
        elif source.startswith(("registry+", "sparse+")):
            prefix = "registry+" if source.startswith("registry+") else "sparse+"
            deps.append(Dep(name, version, "registry",
                            _registry_host(source[len(prefix):])))
        elif source:
            deps.append(Dep(name, version, "unknown", _registry_host(source)))
        else:
            deps.append(Dep(name, version, "path", None))
    return ManifestDoc("", "cargo", tuple(deps))


def _cargo_config(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    redirects: list[tuple[str, str]] = []
    sources = data.get("source") or {}
    if isinstance(sources, dict):
        for name, table in sources.items():
            if not isinstance(table, dict):
                continue
            if table.get("replace-with"):
                redirects.append(("cargo-replace-with", f"{name} -> {table['replace-with']}"))
            if table.get("registry"):
                redirects.append(("cargo-registry", _host(table["registry"]) or table["registry"]))
    # [registries.<name>] index = "sparse+https://host/..." - a named registry
    # a dep can then select by name, and [registry] default = "<name>".
    registries = data.get("registries") or {}
    if isinstance(registries, dict):
        for name, table in registries.items():
            if isinstance(table, dict) and table.get("index"):
                redirects.append(("cargo-registries",
                                  _host(table["index"]) or table["index"]))
    registry = data.get("registry")
    if isinstance(registry, dict) and registry.get("default"):
        redirects.append(("cargo-default-registry", str(registry["default"])))
    return ManifestDoc("", "cargo", (), redirects=tuple(redirects))


def _json_object(text: str) -> dict:
    """Parse JSON that must be an object; a top-level array is not a manifest."""
    data = load_json(text)
    if not isinstance(data, dict):
        raise TypeError("manifest is not a JSON object")
    return data


def _json_deps(section) -> list[Dep]:
    deps = []
    if not isinstance(section, dict):
        return deps
    for name, value in section.items():
        if not isinstance(value, str):
            continue
        v = value.strip()
        low = v.lower()
        if low.startswith(("github:", "gitlab:", "bitbucket:")):
            forge = low.split(":", 1)[0]
            host = {"github": "github.com", "gitlab": "gitlab.com",
                    "bitbucket": "bitbucket.org"}[forge]
            deps.append(Dep(name, None, "git", host))
        elif (re.fullmatch(r"[\w.-]+/[\w.-]+(?:#.*)?", v)
                and "://" not in v and not v.startswith((".", "/"))):
            # npm's `user/repo` GitHub shorthand (not a relative path).
            deps.append(Dep(name, None, "git", "github.com"))
        elif low.startswith(("git+", "git://", "git:")) or v.startswith("git@"):
            deps.append(Dep(name, None, "git", _host(v)))
        elif low.startswith(("file:", "link:")):
            deps.append(Dep(name, None, "path", None))
        elif low.startswith("npm:"):
            deps.append(Dep(name, None, "registry", None))
        elif "://" in v:
            deps.append(Dep(name, None, "git", _host(v)))
        else:
            deps.append(Dep(name, v, "registry", None))
    return deps


def _npm_package_json(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "overrides", "resolutions"):
        deps.extend(_json_deps(data.get(key)))
    return ManifestDoc("", "npm", tuple(deps))


_NODE_MODULES_RE = re.compile(r"(?:^|node_modules/)(@?[^/]+)(?:/|$)")


def _npm_lock(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = ""
            m = _NODE_MODULES_RE.search(key)
            if m:
                name = m.group(1)
            elif key.startswith("@"):
                name = key
            resolved = entry.get("resolved", "") or entry.get("from", "")
            kind, host = _url_source(resolved)
            deps.append(Dep(name, entry.get("version"), kind, host))
    deps_section = data.get("dependencies")
    if isinstance(deps_section, dict):  # lockfile v1
        for name, entry in deps_section.items():
            if not isinstance(entry, dict):
                continue
            resolved = entry.get("resolved", "") or entry.get("from", "")
            kind, host = _url_source(resolved)
            deps.append(Dep(name, entry.get("version"), kind, host))
    return ManifestDoc("", "npm", tuple(deps))


_NPMRC_RE = re.compile(r"^\s*(?P<scope>@[\w.-]+:)?registry\s*=\s*(?P<url>\S+)\s*$",
                       re.MULTILINE | re.IGNORECASE)
_NPMRC_HOST_RE = re.compile(r"^\s*//(?P<host>[^/\s:]+)(?:[/:].*)?$",
                            re.MULTILINE | re.IGNORECASE)


def _npmrc(text: str) -> ManifestDoc | None:
    redirects = []
    for m in _NPMRC_RE.finditer(text):
        url = m.group("url")
        if _is_default_registry(url):
            continue
        redirects.append(("npm-registry", _host(url) or url))
    # `//host/:_authToken=...` names a registry the resolver talks to.
    for m in _NPMRC_HOST_RE.finditer(text):
        host = m.group("host").lower()
        if _is_default_registry(host):
            continue
        redirects.append(("npm-registry-auth", host))
    return ManifestDoc("", "npm", (), redirects=tuple(redirects))


_YARN_URL_RE = re.compile(r"(?:git\+https|git\+ssh|git\+|https?)://[^\s'\"]+")


def _yarn_lock(text: str) -> ManifestDoc | None:
    deps = []
    name = None
    for line in split_lines(text):
        if not line.strip():
            continue
        if not line[0].isspace():
            # `name@range, name@range2:` (v1) or `"name@npm:1":` (berry)
            spec = line.split(",", 1)[0].rsplit(":", 1)[0].strip().strip('"')
            name = spec.rsplit("@", 1)[0] if "@" in spec else spec
            name = name.lstrip("@")
        else:
            if not name:
                continue
            for url in _YARN_URL_RE.findall(line):
                if _is_default_registry(url):
                    continue
                deps.append(Dep(name, None, "git", _host(url)))
    return ManifestDoc("", "npm", tuple(deps))


_PNPM_URL_RE = re.compile(r"(?:git\+https|git\+ssh|git\+|https?)://[^\s'\"#]+")
_PNPM_NAME_RE = re.compile(r"/(@?[\w.-]+(?:/[\w.-]+)?)@")


def _pnpm_lock(text: str) -> ManifestDoc | None:
    """pnpm-lock.yaml is YAML; read it line-class (no YAML dependency)."""
    deps = []
    for line in split_lines(text):
        m = _PNPM_NAME_RE.search(line)
        name = m.group(1) if m else ""
        for url in _PNPM_URL_RE.findall(line):
            if _is_default_registry(url):
                continue
            deps.append(Dep(name, None, "git", _host(url)))
    return ManifestDoc("", "npm", tuple(deps))


def _pyproject(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps: list[Dep] = []
    redirects: list[tuple[str, str]] = []
    project = data.get("project") or {}
    for raw in project.get("dependencies", ()) or ():
        dep = _pep508(str(raw))
        if dep:
            deps.append(dep)
    optional = project.get("optional-dependencies") or {}
    for values in optional.values():
        for raw in values or ():
            dep = _pep508(str(raw))
            if dep:
                deps.append(dep)
    # PEP 735 dependency groups (a top-level table, not under [project]).
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for values in groups.values():
            for raw in values or ():
                if isinstance(raw, str):
                    dep = _pep508(raw)
                    if dep:
                        deps.append(dep)
    build = data.get("build-system") or {}
    for raw in build.get("requires", ()) or ():
        dep = _pep508(str(raw))
        if dep:
            deps.append(dep)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for table in _poetry_dep_tables(poetry):
        for name, value in table.items():
            if name.lower() == "python":
                continue
            if isinstance(value, str):
                deps.append(Dep(name, value, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    deps.append(Dep(name, value.get("version"), "git", _host(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    # uv / poetry index redirects and uv source overrides
    uv = (data.get("tool") or {}).get("uv") or {}
    for index in uv.get("index", ()) or ():
        if isinstance(index, dict) and index.get("url"):
            if not _is_default_registry(index["url"]):
                redirects.append(("uv-index", _host(index["url"]) or index["url"]))
    for name, src in (uv.get("sources") or {}).items():
        deps.extend(_source_dep(name, src))
    for key in ("dev-dependencies", "constraint-dependencies",
                "override-dependencies", "build-constraint-dependencies"):
        for raw in _as_list(uv.get(key)):
            dep = _pep508(str(raw))
            if dep and dep.name:
                deps.append(dep)
    # pdm dev groups
    pdm = (data.get("tool") or {}).get("pdm") or {}
    for values in (pdm.get("dev-dependencies") or {}).values() \
            if isinstance(pdm.get("dev-dependencies"), dict) else ():
        for raw in _as_list(values):
            dep = _pep508(str(raw))
            if dep and dep.name:
                deps.append(dep)
    # hatch environments
    hatch = (data.get("tool") or {}).get("hatch") or {}
    envs = hatch.get("envs") if isinstance(hatch, dict) else None
    if isinstance(envs, dict):
        for entry in envs.values():
            if isinstance(entry, dict):
                for raw in _as_list(entry.get("dependencies")):
                    dep = _pep508(str(raw))
                    if dep and dep.name:
                        deps.append(dep)
    # flit metadata requirements
    flit = (data.get("tool") or {}).get("flit") or {}
    flit_meta = flit.get("metadata") if isinstance(flit, dict) else None
    if isinstance(flit_meta, dict):
        for key in ("requires", "requires-python"):
            if key == "requires-python":
                continue
            for raw in _as_list(flit_meta.get(key)):
                dep = _pep508(str(raw))
                if dep and dep.name:
                    deps.append(dep)
        for values in (flit_meta.get("requires-extra") or {}).values() \
                if isinstance(flit_meta.get("requires-extra"), dict) else ():
            for raw in _as_list(values):
                dep = _pep508(str(raw))
                if dep and dep.name:
                    deps.append(dep)
    # poetry plugin + build constraints
    for table in (poetry.get("requires-plugins"), poetry.get("build-constraints")):
        if isinstance(table, dict):
            for name, value in table.items():
                deps.append(Dep(name, value if isinstance(value, str) else None,
                                "registry", None))
    # pixi in pyproject ([tool.pixi])
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("pixi"), dict):
        _add_pixi(tool["pixi"], deps, redirects)
    poetry_source = poetry.get("source")
    for _name, table in (poetry_source.items()
                         if isinstance(poetry_source, dict) else ()):
        if isinstance(table, dict) and table.get("url"):
            if not _is_default_registry(table["url"]):
                redirects.append(("poetry-source", _host(table["url"]) or table["url"]))
    return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))


def _poetry_dep_tables(poetry: dict):
    if isinstance(poetry.get("dependencies"), dict):
        yield poetry["dependencies"]
    group = poetry.get("group")
    if isinstance(group, dict):
        for entry in group.values():
            if isinstance(entry, dict) and isinstance(entry.get("dependencies"), dict):
                yield entry["dependencies"]
    dev = poetry.get("dev-dependencies")
    if isinstance(dev, dict):
        yield dev


_PIP_OPTION_RE = re.compile(
    r"^\s*(?:(?:--(?:extra-)?index-url|-i)\s*=?\s*(?P<index>\S+)"
    r"|--trusted-host\s+(?P<trusted>\S+)"
    r"|(?:-f|--find-links)\s*=?\s*(?P<find>\S+)"
    r"|(?:-r|--requirement|-c|--constraint)\s*=?\s*(?P<include>\S+))",
    re.MULTILINE | re.IGNORECASE,
)


def _requirements(text: str) -> ManifestDoc | None:
    deps = []
    redirects = []
    text = re.sub(r"\\\r?\n", " ", text)  # join line continuations
    for m in _PIP_OPTION_RE.finditer(text):
        if m.group("trusted"):
            redirects.append(("pip-trusted-host", _host(m.group("trusted")) or m.group("trusted")))
            continue
        index = m.group("index")
        if index and not _is_default_registry(index):
            redirects.append(("pip-index-url", _host(index) or index))
            continue
        find = m.group("find")
        if find and not _is_default_registry(find):
            redirects.append(("pip-find-links", _host(find) or find))
            continue
        include = m.group("include")
        if include and "://" in include and not _is_default_registry(include):
            redirects.append(("pip-requirements-url", _host(include) or include))
    for raw in split_lines(text):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e", "--editable")):
            parts = line.split(None, 1)
            rest = (parts[1] if len(parts) > 1 else "").split(" #", 1)[0].strip()
            dep = _pep508(rest)
            if dep and (dep.name or dep.source_kind == "git"):
                deps.append(dep)
            continue
        if line.startswith("-"):
            continue  # -r/-c includes and other options
        dep = _pep508(line)
        if dep and dep.name:
            deps.append(dep)
        elif dep and dep.source_kind == "git":
            deps.append(dep)
    return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))


def _pipfile(text: str) -> ManifestDoc | None:
    # Pipfile is TOML; Pipfile.lock is JSON.
    stripped = text.lstrip()
    if stripped.startswith("{"):
        data = _json_object(text)
        deps = []
        for section in ("default", "develop"):
            for name, entry in (data.get(section) or {}).items():
                if isinstance(entry, dict):
                    if entry.get("git"):
                        deps.append(Dep(name, entry.get("version"), "git", _host(entry["git"])))
                    elif entry.get("path"):
                        deps.append(Dep(name, entry.get("version"), "path", None))
                    else:
                        deps.append(Dep(name, entry.get("version"), "registry", None))
        redirects = []
        meta = data.get("_meta") or {}
        for src in (meta.get("sources", ()) if isinstance(meta, dict) else ()) or ():
            if isinstance(src, dict) and src.get("url"):
                if not _is_default_registry(src["url"]):
                    redirects.append(("pipfile-source", _host(src["url"]) or src["url"]))
        return ManifestDoc("", "pip", tuple(deps), redirects=tuple(redirects))
    data = load_toml(text)
    deps = []
    for section in ("packages", "dev-packages"):
        for name, value in (data.get(section) or {}).items():
            if isinstance(value, str):
                deps.append(Dep(name, value if value != "*" else None, "registry", None))
            elif isinstance(value, dict):
                if value.get("git"):
                    deps.append(Dep(name, value.get("version"), "git", _host(value["git"])))
                elif value.get("path"):
                    deps.append(Dep(name, value.get("version"), "path", None))
                else:
                    deps.append(Dep(name, value.get("version"), "registry", None))
    return ManifestDoc("", "pip", tuple(deps))


def _poetry_lock(text: str) -> ManifestDoc | None:
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source") or {}
        url = source.get("url", "") if isinstance(source, dict) else ""
        stype = source.get("type", "") if isinstance(source, dict) else ""
        if url and "git" in stype:
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), "git", _host(url)))
        elif url:
            kind, host = _url_source(url)
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), kind, host))
        else:
            deps.append(Dep(pkg.get("name", ""), pkg.get("version"), "registry", None))
    return ManifestDoc("", "pip", tuple(deps))


def _toml_lock(text: str) -> ManifestDoc | None:
    """uv.lock / pdm.lock: ``[[package]]`` with a source dict or git/path key."""
    data = load_toml(text)
    deps = []
    for pkg in data.get("package", ()) or ():
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name", ""), pkg.get("version")
        source = pkg.get("source")
        if isinstance(source, dict):
            if source.get("git"):
                deps.append(Dep(name, version, "git", _host(source["git"])))
            elif source.get("registry"):
                kind, host = _url_source(source["registry"])
                deps.append(Dep(name, version, kind, host))
            elif source.get("url"):
                kind, host = _url_source(source["url"])
                deps.append(Dep(name, version, kind, host))
            elif any(source.get(k) for k in ("path", "editable", "virtual",
                                             "directory")):
                deps.append(Dep(name, version, "path", None))
            else:
                deps.append(Dep(name, version, "registry", None))
        elif pkg.get("git"):
            deps.append(Dep(name, version, "git", _host(pkg["git"])))
        elif pkg.get("path"):
            deps.append(Dep(name, version, "path", None))
        else:
            deps.append(Dep(name, version, "registry", None))
    return ManifestDoc("", "pip", tuple(deps))


_YARNRC_RE = re.compile(
    r"npmRegistryServer\s*:\s*\"?(?P<url>[^\s\"']+)\"?",
    re.IGNORECASE,
)


def _yarnrc(text: str) -> ManifestDoc | None:
    redirects = []
    for m in _YARNRC_RE.finditer(text):
        url = m.group("url")
        if _is_default_registry(url):
            continue
        redirects.append(("yarn-registry", _host(url) or url))
    return ManifestDoc("", "npm", (), redirects=tuple(redirects))


_GO_REQUIRE_RE = re.compile(r"^\s*require\s+(?!\()(\S+)\s+(\S+)", re.MULTILINE)
_GO_BLOCK_RE = re.compile(r"require\s*\((.*?)\)", re.DOTALL)
_GO_REPLACE_RE = re.compile(r"^\s*replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)", re.MULTILINE)


def _go_mod(text: str) -> ManifestDoc | None:
    deps = []
    for name, version in _GO_REQUIRE_RE.findall(text):
        deps.append(Dep(name, version, "registry", None))
    for block in _GO_BLOCK_RE.findall(text):
        for raw in split_lines(block):
            parts = raw.split()
            if len(parts) >= 2:
                deps.append(Dep(parts[0], parts[1], "registry", None))
    replaced = {m.group(1): m.group(2) for m in _GO_REPLACE_RE.finditer(text)}
    out = []
    for dep in deps:
        target = replaced.get(dep.name)
        if target and _is_go_path(target):
            out.append(Dep(dep.name, dep.constraint, "path", None))
        else:
            out.append(dep)
    return ManifestDoc("", "go", tuple(out))


def _is_go_path(target: str) -> bool:
    """A go ``replace`` target is a filesystem path, not another module."""
    if target.startswith(("./", "../", "/", ".")):
        return True
    if "://" in target:
        return True
    return "/" not in target


def _go_sum(text: str) -> ManifestDoc | None:
    deps = []
    seen = set()
    for raw in split_lines(text):
        parts = raw.split()
        if len(parts) >= 2:
            key = (parts[0], parts[1])
            if key in seen:
                continue
            seen.add(key)
            deps.append(Dep(parts[0], parts[1], "registry", None))
    return ManifestDoc("", "go", tuple(deps))


_GEM_LINE_RE = re.compile(r"^\s*gem\s+['\"]([\w.-]+)['\"](.*)$", re.MULTILINE)
_GEM_SOURCE_RE = re.compile(r"^\s*source\s+['\"]([^'\"]+)['\"]", re.MULTILINE)


def _gemfile(text: str) -> ManifestDoc | None:
    deps = []
    for m in _GEM_LINE_RE.finditer(text):
        name, rest = m.group(1), m.group(2)
        constraint = None
        cm = re.search(r"['\"]([~><=][^'\"]*)['\"]", rest)
        if cm:
            constraint = cm.group(1)
        git = re.search(r"git:\s*['\"]([^'\"]+)", rest)
        shorthand = re.search(r"(github|gitlab|bitbucket):\s*['\"]([^'\"]+)", rest)
        if git:
            deps.append(Dep(name, constraint, "git", _host(git.group(1))))
        elif shorthand:
            host = {"github": "github.com", "gitlab": "gitlab.com",
                    "bitbucket": "bitbucket.org"}[shorthand.group(1)]
            deps.append(Dep(name, constraint, "git", host))
        elif re.search(r"path:\s*['\"]", rest):
            deps.append(Dep(name, constraint, "path", None))
        else:
            deps.append(Dep(name, constraint, "registry", None))
    redirects = []
    for m in _GEM_SOURCE_RE.finditer(text):
        url = m.group(1)
        if "rubygems.org" not in url:
            redirects.append(("gem-source", _host(url) or url))
    return ManifestDoc("", "gem", tuple(deps), redirects=tuple(redirects))


_GEMLOCK_SPEC_RE = re.compile(r"^\s{4}([\w.-]+)\s+\(")


def _gemfile_lock(text: str) -> ManifestDoc | None:
    deps = []
    mode = ""
    remote = None
    for line in split_lines(text):
        if line and not line[0].isspace():
            mode = line.strip()
            remote = None
        elif mode in ("GIT", "PATH") and line.strip().startswith("remote:"):
            remote = line.split(":", 1)[1].strip()
        else:
            m = _GEMLOCK_SPEC_RE.match(line)
            if m:
                kind = "git" if mode == "GIT" and remote else (
                    "path" if mode == "PATH" else "registry")
                deps.append(Dep(m.group(1), None, kind,
                                _host(remote) if remote and kind == "git" else None))
    return ManifestDoc("", "gem", tuple(deps))


_PLATFORM_PREFIXES = ("php", "hhvm", "ext-", "lib-", "composer-",
                      "composer-plugin-api", "composer-runtime-api")


def _composer_json(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for key in ("require", "require-dev"):
        for name, value in (data.get(key) or {}).items():
            if name.startswith(_PLATFORM_PREFIXES):
                continue
            if isinstance(value, str) and ("://" in value or value.startswith(("dev-",))):
                if "://" in value:
                    deps.append(Dep(name, None, "git", _host(value)))
                else:
                    deps.append(Dep(name, value, "registry", None))
            else:
                deps.append(Dep(name, value if isinstance(value, str) else None,
                                "registry", None))
    redirects = []
    for repo in data.get("repositories", ()) or ():
        if isinstance(repo, dict) and repo.get("url"):
            redirects.append(("composer-repository", _host(repo["url"]) or repo["url"]))
    return ManifestDoc("", "composer", tuple(deps), redirects=tuple(redirects))


def _composer_lock(text: str) -> ManifestDoc | None:
    data = _json_object(text)
    deps = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, ()) or ():
            if not isinstance(pkg, dict):
                continue
            source = pkg.get("source") or {}
            url = source.get("url", "") if isinstance(source, dict) else ""
            name = pkg.get("name", "")
            if url and ("://" in url):
                deps.append(Dep(name, pkg.get("version"), "git", _host(url)))
            else:
                deps.append(Dep(name, pkg.get("version"), "registry", None))
    return ManifestDoc("", "composer", tuple(deps))


# ---------------------------------------------------------------------------
# Python: PEP 751, uv/pdm/conda/pixi, legacy setup/tox/ini
# ---------------------------------------------------------------------------


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
    name = re.split(r"[=<>!~\s]", text, 1)[0].strip()
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


# ---------------------------------------------------------------------------
# Other languages: XML (Maven/.NET), YAML, JSONC, TOML and DSL manifests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Remaining languages: regex extraction over their declarative files
# ---------------------------------------------------------------------------

_ZIG_URL_RE = re.compile(r"\.url\s*=\s*\"([^\"]+)\"")
_NIMBLE_RE = re.compile(r"requires\s+[\"']([^\"']+)[\"']")
_ROCK_DEP_RE = re.compile(r"[\"']([A-Za-z0-9_.-]+)\s*[><=~]+\s*([0-9][0-9.]*)[\"']")
_CLOJURE_COORD_RE = re.compile(r"\[([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s+\"([^\"]+)\"\]")
_CLOJURE_GIT_RE = re.compile(r":git/url\s+\"([^\"]+)\"")
# Anchored on the rare literal key, not on a leading name class, so the scan
# is linear on a long line (the regex-safety gate rejects the latter).
_CLOJURE_MVN_MAP_RE = re.compile(r":mvn/version\s+\"([^\"]+)\"")
_COORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_DUNE_DEPS_RE = re.compile(r"\(depends((?:\s+[A-Za-z0-9_.-]+)+)\)")
_REBAR_DEP_RE = re.compile(r"\{\s*([a-z0-9_]+)\s*,\s*\"([^\"]+)\"")
_CART_GIT_RE = re.compile(r"\bgit\s+\"([^\"]+)\"")
_CART_FORGE_RE = re.compile(r"\b(?:github|gitlab|bitbucket)\s+\"([^\"/]+/[^\"]+)\"")
_CABAL_LOCATION_RE = re.compile(r"location:\s*(\S+)")
_CMAKE_URL_RE = re.compile(r"\b(?:URL|GIT_REPOSITORY)\s+\"?([^\"\s)]+)\"?")
_MESON_DEP_RE = re.compile(r"dependency\(\s*[\"']([^\"']+)")
_BAZEL_DEP_RE = re.compile(
    r"bazel_dep\(\s*name\s*=\s*\"([^\"]+)\""
    r"(?:\s*,\s*version\s*=\s*\"([^\"]+)\")?")


def _coord_before(text: str, index: int) -> str:
    """The ``group/artifact`` (or Clojure coordinate) ending just before *index*."""
    head = text[:index].rstrip()
    if head.endswith("{"):
        head = head[:-1].rstrip()
    token = head.rsplit(None, 1)[-1] if head else ""
    parts = token.split("/")
    if len(parts) == 2 and all(
            part and set(part) <= _COORD_CHARS for part in parts):
        return token
    return ""


def _zig_zon(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _ZIG_URL_RE.finditer(text)]
    return ManifestDoc("", "zig", tuple(deps))


def _nimble(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1).split(" ")[0].split(">")[0].strip(), None, "registry", None)
            for m in _NIMBLE_RE.finditer(text)]
    return ManifestDoc("", "nim", tuple(deps))


def _rockspec(text: str) -> ManifestDoc | None:
    deps = [Dep(name, version or None, "registry", None)
            for name, version in _ROCK_DEP_RE.findall(text)]
    return ManifestDoc("", "lua", tuple(deps))


def _clojure(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _CLOJURE_COORD_RE.finditer(text)]
    for m in _CLOJURE_MVN_MAP_RE.finditer(text):
        deps.append(Dep(_coord_before(text, m.start()), m.group(1), "registry", None))
    for m in _CLOJURE_GIT_RE.finditer(text):
        deps.append(Dep(_coord_before(text, m.start()), None, "git", _host(m.group(1))))
    return ManifestDoc("", "clojure", tuple(deps))
    return ManifestDoc("", "clojure", tuple(deps))


def _dune_project(text: str) -> ManifestDoc | None:
    deps: list[Dep] = []
    for match in _DUNE_DEPS_RE.finditer(text):
        for name in match.group(1).split():
            deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "ocaml", tuple(deps))


def _rebar(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _REBAR_DEP_RE.finditer(text)]
    return ManifestDoc("", "elixir", tuple(deps))

def _cartfile(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CART_GIT_RE.finditer(text)]
    deps += [Dep(m.group(1).rsplit("/", 1)[-1], None, "git", "github.com")
             for m in _CART_FORGE_RE.finditer(text)]
    return ManifestDoc("", "swift", tuple(deps))


def _cabal_project(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CABAL_LOCATION_RE.finditer(text)]
    return ManifestDoc("", "haskell", tuple(deps))


def _cmake(text: str) -> ManifestDoc | None:
    deps = [Dep("", None, "git", _host(m.group(1)))
            for m in _CMAKE_URL_RE.finditer(text) if "://" in m.group(1)]
    return ManifestDoc("", "cpp", tuple(deps))


def _meson(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), None, "registry", None)
            for m in _MESON_DEP_RE.finditer(text)]
    return ManifestDoc("", "cpp", tuple(deps))


def _bazel(text: str) -> ManifestDoc | None:
    deps = [Dep(m.group(1), m.group(2), "registry", None)
            for m in _BAZEL_DEP_RE.finditer(text)]
    return ManifestDoc("", "bazel", tuple(deps))


def _perl_meta(text: str) -> ManifestDoc | None:
    try:
        data = load_json(text)
    except ManifestSyntaxError:
        data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "perl", unresolved=("not a mapping",))
    deps: list[Dep] = []
    prereqs = data.get("prereqs")
    if isinstance(prereqs, dict):
        for phase in prereqs.values():
            if isinstance(phase, dict):
                for name in (phase.get("requires") or {}):
                    deps.append(Dep(name, None, "registry", None))
    for section in ("requires", "dependencies"):
        table = data.get(section)
        if isinstance(table, dict):
            for name in table:
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "perl", tuple(deps))


def _dub(text: str) -> ManifestDoc | None:
    data = load_json(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "d", unresolved=("not an object",))
    deps: list[Dep] = []
    for name, value in (data.get("dependencies") or {}).items():
        if isinstance(value, str):
            deps.append(Dep(name, value, "registry", None))
        elif isinstance(value, dict):
            deps.extend(_source_dep(name, value)
                        or [Dep(name, None, "registry", None)])
    return ManifestDoc("", "d", tuple(deps))


def _stack_yaml(text: str) -> ManifestDoc | None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "haskell", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for entry in data.get("extra-deps", ()) or ():
        if isinstance(entry, str):
            deps.append(Dep(entry.rsplit("-", 1)[0], None, "registry", None))
        elif isinstance(entry, dict):
            name = entry.get("name") or ""
            git = entry.get("git")
            github = entry.get("github")
            if git is None and github is None and entry:
                # `- evil:\n    git: ...` parses as {name: {git: ...}}
                sole_name, spec = next(iter(entry.items()))
                if isinstance(spec, dict):
                    name = name or sole_name
                    git = spec.get("git")
                    github = spec.get("github")
            if git:
                deps.append(Dep(name, None, "git", _host(str(git))))
            elif github:
                deps.append(Dep(name, None, "git", "github.com"))
    return ManifestDoc("", "haskell", tuple(deps))


def _package_yaml(text: str) -> ManifestDoc | None:
    """hpack ``package.yaml``: ``dependencies`` list of names."""
    data = load_yaml(text)
    if not isinstance(data, dict):
        return ManifestDoc("", "haskell", unresolved=("not a mapping",))
    deps: list[Dep] = []
    for value in data.get("dependencies", ()) or ():
        if isinstance(value, str):
            deps.append(Dep(value.split(" ")[0].split(">")[0], None, "registry", None))
        elif isinstance(value, dict):
            for name in value:
                deps.append(Dep(name, None, "registry", None))
    return ManifestDoc("", "haskell", tuple(deps))


_PARSERS = {
    "cargo": _cargo_toml,        # overridden per-filename below
    "npm": _npm_package_json,
    "pip": _requirements,
    "go": _go_mod,
    "gem": _gemfile,
    "composer": _composer_json,
    "conda": _conda_env,
    "jvm": _maven_pom,
    "dotnet": _dotnet_project,
    "dart": _pubspec,
    "crystal": _shard_yml,
    "cpp": _conan,
    "julia": _julia_project,
}

#: Filename-specific parsers that refine the format default.
_BY_NAME = {
    "cargo.lock": _cargo_lock,
    "cargo/config.toml": _cargo_config,
    "cargo/config": _cargo_config,
    ".cargo/config.toml": _cargo_config,
    ".cargo/config": _cargo_config,
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    ".yarnrc.yml": _yarnrc,
    ".npmrc": _npmrc,
    "pyproject.toml": _pyproject,
    "requirements.txt": _requirements,
    "constraints.txt": _requirements,
    "pipfile": _pipfile,
    "pipfile.lock": _pipfile,
    "poetry.lock": _poetry_lock,
    "uv.lock": _toml_lock,
    "pdm.lock": _toml_lock,
    "uv.toml": _uv_toml,
    "pylock.toml": _pylock,
    "pylock.*.toml": _pylock,
    "setup.py": _setup_py,
    "setup.cfg": _setup_cfg,
    "tox.ini": _tox_ini,
    "noxfile.py": _noxfile,
    "environment.yml": _conda_env,
    "environment.yaml": _conda_env,
    "meta.yaml": _conda_meta,
    "pixi.toml": _pixi,
    "pip.conf": _pip_config,
    "pip.ini": _pip_config,
    ".pip/pip.conf": _pip_config,
    ".config/pip/pip.conf": _pip_config,
    ".pypirc": _pypirc,
    "go.sum": _go_sum,
    "go.work.sum": _go_sum,
    "gemfile.lock": _gemfile_lock,
    "*.gemspec": _gemspec,
    "composer.lock": _composer_lock,
    "pom.xml": _maven_pom,
    "*.csproj": _dotnet_project,
    "*.fsproj": _dotnet_project,
    "*.vbproj": _dotnet_project,
    "directory.packages.props": _dotnet_project,
    "packages.config": _packages_config,
    "nuget.config": _nuget_config,
    "pubspec.yaml": _pubspec,
    "pubspec.lock": _pubspec_lock,
    "shard.yml": _shard_yml,
    "shard.lock": _shard_lock,
    "deno.json": _deno_json,
    "deno.jsonc": _deno_json,
    "bun.lock": _bun_lock,
    "project.toml": _julia_project,
    "manifest.toml": _julia_manifest,
    "gradle/libs.versions.toml": _gradle_libs,
    "build.gradle": _gradle_dsl,
    "build.gradle.kts": _gradle_dsl,
    "settings.gradle": _gradle_dsl,
    "settings.gradle.kts": _gradle_dsl,
    "vcpkg.json": _vcpkg,
    "*.cabal": _cabal,
    "*.opam": _opam,
    "mix.exs": _mix_exs,
    "mix.lock": _mix_lock,
    "conanfile.txt": _conan,
    "description": _r_description,
    "renv.lock": _renv_lock,
    "cpanfile": _cpanfile,
    "fpm.toml": _fpm_toml,
    "gleam.toml": _gleam_toml,
    "package.resolved": _swift_resolved,
    "package.swift": _swift_package,
    "podfile": _podfile,
    "build.zig.zon": _zig_zon,
    "dub.json": _dub,
    "*.nimble": _nimble,
    "*.rockspec": _rockspec,
    "deps.edn": _clojure,
    "project.clj": _clojure,
    "dune-project": _dune_project,
    "rebar.config": _rebar,
    "rebar.lock": _rebar,
    "cartfile": _cartfile,
    "cartfile.resolved": _cartfile,
    "cabal.project": _cabal_project,
    "cabal.project.freeze": _cabal_project,
    "cmakelists.txt": _cmake,
    "meson.build": _meson,
    "module.bazel": _bazel,
    "meta.json": _perl_meta,
    "meta.yml": _perl_meta,
    "stack.yaml": _stack_yaml,
    "stack.yaml.lock": _stack_yaml,
    "package.yaml": _package_yaml,
}


def _text_parser_for(path: str, text: str):
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    if base in _BY_NAME:
        return _BY_NAME[base]
    best_fn = None
    best_key: tuple[int, int] | None = None
    for name, fn in _BY_NAME.items():
        if not _matches(lowered, base, name):
            continue
        key = _glob_rank(name)
        if best_key is None or key < best_key:
            best_key, best_fn = key, fn
    if best_fn is not None:
        return best_fn
    fmt = manifest_format(path)
    return _PARSERS.get(fmt or "", _requirements)


def lowered_matches(path: str, name: str) -> bool:
    lowered = path.lower()
    base = lowered.rsplit("/", 1)[-1]
    return _matches(lowered, base, name.lower())


def parse_manifest(path: str, text: str) -> ManifestDoc | None:
    """Parse *path*'s committed bytes into a :class:`ManifestDoc`.

    Returns None when *path* is not a manifest.  A malformed or oversized
    manifest returns a doc with ``dependencies=()`` and a named ``unresolved``
    entry, never raising and never silently skipping.
    """
    fmt = manifest_format(path)
    if fmt is None:
        return None
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        return ManifestDoc(path, fmt, unresolved=("over the byte cap",))
    if text.startswith("\ufeff"):  # a BOM would break tomllib/json
        text = text.lstrip("\ufeff")
    parser = _text_parser_for(path, text)
    try:
        doc = parser(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, ValueError,
            ManifestSyntaxError, TypeError, KeyError, AttributeError,
            IndexError, RecursionError, OverflowError, MemoryError) as exc:
        return ManifestDoc(path, fmt, unresolved=(f"malformed: {type(exc).__name__}",))
    if doc is None:
        return ManifestDoc(path, fmt, unresolved=("unparsed",))
    doc.path = path
    return doc
