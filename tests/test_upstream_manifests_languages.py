"""Cross-language manifest coverage: every ecosystem's dependency files.

Each parser is pinned to one shape here; the safety of the syntax loaders is
tested separately in ``test_manifest_syntax.py`` and in the security gates.
"""

from __future__ import annotations

import pytest

from trustsight.analysis.manifests import manifest_format, parse_manifest
from trustsight.analysis.pipeline import scan_diff


def _by_name(path, text):
    doc = parse_manifest(path, text)
    return {d.name: d for d in doc.dependencies}


@pytest.mark.parametrize("path, fmt", [
    ("pom.xml", "jvm"),
    ("build.gradle", "jvm"),
    ("App.csproj", "dotnet"),
    ("packages.config", "dotnet"),
    ("pubspec.yaml", "dart"),
    ("shard.yml", "crystal"),
    ("deno.json", "npm"),
    ("bun.lock", "npm"),
    ("Project.toml", "julia"),
    ("Manifest.toml", "julia"),
    ("vcpkg.json", "cpp"),
    ("mypkg.cabal", "haskell"),
    ("mypkg.opam", "ocaml"),
    ("mix.exs", "elixir"),
    ("conanfile.txt", "cpp"),
    ("DESCRIPTION", "r"),
    ("renv.lock", "r"),
    ("cpanfile", "perl"),
    ("mypkg.gemspec", "gem"),
    ("fpm.toml", "fortran"),
    ("gleam.toml", "gleam"),
    ("Package.resolved", "swift"),
    ("Podfile", "swift"),
])
def test_language_manifest_is_recognised(path, fmt):
    assert manifest_format(path) == fmt


def test_maven_pom_dependencies_and_repositories():
    doc = parse_manifest("pom.xml", (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<dependencies>"
        "<dependency><groupId>org.x</groupId><artifactId>y</artifactId>"
        "<version>1.2</version></dependency>"
        "</dependencies>"
        "<repositories><repository><url>https://evil.example/maven</url>"
        "</repository></repositories>"
        "</project>"))
    by = _by_name("pom.xml", (
        '<project><dependencies><dependency><groupId>org.x</groupId>'
        "<artifactId>y</artifactId><version>1.2</version></dependency>"
        "</dependencies></project>"))
    assert "org.x:y" in by
    assert ("maven-repository", "evil.example") in doc.redirects


def test_dotnet_project_and_nuget_config():
    by = _by_name("App.csproj", (
        '<Project Sdk="Microsoft.NET.Sdk">'
        '<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
        '<PackageReference Include="X"><Version>1.0</Version></PackageReference>'
        "</ItemGroup></Project>"))
    assert set(by) == {"Newtonsoft.Json", "X"}
    redirects = parse_manifest("NuGet.config", (
        '<configuration><packageSources>'
        '<add key="x" value="https://evil.example/nuget" />'
        "</packageSources></configuration>")).redirects
    assert ("nuget-source", "evil.example") in redirects


def test_dart_yaml_and_lock():
    by = _by_name("pubspec.yaml", (
        "dependencies:\n  http: ^1.0.0\n"
        "  evil:\n    git: https://evil.example/ev\n"
        "dev_dependencies:\n  test: any\n"))
    assert by["http"].source_kind == "registry"
    assert by["evil"].remote == "evil.example"
    lock = _by_name("pubspec.lock", (
        "packages:\n  evil:\n    source: git\n"
        "    url: https://evil.example/ev\n    version: '1.0'\n"))
    assert lock["evil"].remote == "evil.example"


def test_crystal_shard_and_lock():
    by = _by_name("shard.yml", (
        "dependencies:\n  evil:\n    git: https://evil.example/ev\n"
        "  local:\n    path: ../local\n"))
    assert by["evil"].remote == "evil.example"
    assert by["local"].source_kind == "path"


def test_deno_imports_and_bun_lock():
    by = _by_name("deno.json", (
        '{"imports": {"std/": "https://deno.land/std@0.1/",'
        ' "evil": "https://evil.example/mod.ts", "jsr": "jsr:@scope/x"}}'))
    assert by["std/"].remote == "deno.land"
    assert by["evil"].remote == "evil.example"
    assert by["jsr"].source_kind == "registry"
    bun = _by_name("bun.lock", (
        '{"packages": {"evil@1.0": {"version": "1.0",'
        ' "resolved": "https://evil.example/evil-1.0.tgz"}}}'))
    assert bun["evil"].remote == "evil.example"


def test_julia_project_and_manifest():
    assert set(_by_name("Project.toml", '[deps]\nJSON = "x"\nYAML = "y"\n')) == {
        "JSON", "YAML"}
    assert set(_by_name("Manifest.toml", (
        '[[deps.JSON]]\nuuid = "x"\nversion = "0.21"\n'))) == {"JSON"}


def test_jvm_gradle_libs_and_dsl():
    by = _by_name("gradle/libs.versions.toml", (
        "[libraries]\njson = { module = \"org.x:y\", version = \"1.0\" }\n"))
    assert "org.x:y" in by
    by = _by_name("build.gradle",
                  "dependencies {\n  implementation 'org.x:y:1.2'\n}\n")
    assert "org.x:y" in by


def test_cpp_vcpkg_and_conan():
    by = _by_name("vcpkg.json",
                  '{"dependencies": ["fmt", {"name": "zlib"}]}')
    assert set(by) == {"fmt", "zlib"}
    by = _by_name("conanfile.txt", "[requires]\nboost/1.83\nzlib/1.3\n")
    assert set(by) == {"boost", "zlib"}


def test_haskell_cabal_and_ocaml_opam():
    by = _by_name("mypkg.cabal", (
        "library\n  build-depends:\n    base >=4.14,\n    text ^>=1.2\n"))
    assert {"base", "text"} <= set(by)
    by = _by_name("mypkg.opam", (
        'depends: [\n  "dune" {>= "3.0"}\n  "lwt"\n]\n'))
    assert {"dune", "lwt"} <= set(by)


def test_elixir_mix_exs_and_lock():
    by = _by_name("mix.exs", (
        "defp deps do\n  [\n    {:plug, \"~> 1.0\"},\n"
        "    {:evil, git: \"https://evil.example/ev\"}\n  ]\nend\n"))
    assert by["plug"].source_kind == "registry"
    assert by["evil"].remote == "evil.example"
    by = _by_name("mix.lock", (
        '%{"hex:plug": {:hex, :plug, "1.0.0", "sha", [:mix], [], "hexpm"},}\n'))
    assert by["plug"].constraint == "1.0.0"


def test_r_description_and_renv_lock():
    by = _by_name("DESCRIPTION", (
        "Package: x\nDepends: R (>= 3.5), methods\n"
        "Imports:\n    ggplot2 (>= 3.0),\n    dplyr\n"))
    assert {"methods", "ggplot2", "dplyr"} <= set(by)
    by = _by_name("renv.lock", (
        '{"Packages": {"evil": {"Version": "1.0", "Source": "GitHub",'
        ' "Repository": "https://evil.example/ev"}}}'))
    assert by["evil"].remote == "evil.example"


def test_perl_cpanfile_and_ruby_gemspec():
    by = _by_name("cpanfile", "requires 'Moo', '2.0';\ntest_requires 'Test::More';\n")
    assert {"Moo", "Test::More"} <= set(by)
    by = _by_name("mypkg.gemspec", (
        "spec.add_dependency 'rails', '~> 7.0'\n"
        "spec.add_development_dependency 'rspec'\n"))
    assert {"rails", "rspec"} <= set(by)


def test_swift_resolved_package_and_podfile():
    by = _by_name("Package.resolved", (
        '{"pins": [{"identity": "evil",'
        ' "location": "https://evil.example/evil.git"}]}'))
    assert by["evil"].remote == "evil.example"
    by = _by_name("Package.swift", (
        'let package = Package(dependencies: ['
        '.package(url: "https://evil.example/swift-x.git", from: "1.0.0")])'))
    assert by["swift-x"].remote == "evil.example"
    doc = parse_manifest("Podfile", (
        "source 'https://evil.example/specs'\n"
        "pod 'Alamofire', :git => 'https://evil.example/af.git'\n"))
    assert ("pod-source", "evil.example") in doc.redirects
    assert {d.name for d in doc.dependencies} == {"Alamofire"}


def test_swift_package_git_host_fires_u003():
    diff = ("--- /dev/null\n+++ b/Package.swift\n@@ -0,0 +1,2 @@\n"
            "+let package = Package(dependencies: [\n"
            '+.package(url: "https://evil.example/x.git", from: "1.0.0")])\n')
    fact = scan_diff(diff, package_name="p")
    ids = {entry.rule_id for entry in fact.score_breakdown}
    assert "U003" in ids


@pytest.mark.parametrize("path, fmt", [
    ("build.zig.zon", "zig"),
    ("dub.json", "d"),
    ("mypkg.nimble", "nim"),
    ("mypkg-1.0-1.rockspec", "lua"),
    ("deps.edn", "clojure"),
    ("project.clj", "clojure"),
    ("dune-project", "ocaml"),
    ("rebar.config", "elixir"),
    ("Cartfile", "swift"),
    ("cabal.project", "haskell"),
    ("CMakeLists.txt", "cpp"),
    ("meson.build", "cpp"),
    ("MODULE.bazel", "bazel"),
    ("META.json", "perl"),
    ("stack.yaml", "haskell"),
    ("package.yaml", "haskell"),
])
def test_more_language_manifests_recognised(path, fmt):
    assert manifest_format(path) == fmt


def test_zig_dub_nim_lua():
    deps = parse_manifest("build.zig.zon", (
        '.{\n .name = .x,\n .dependencies = .{\n'
        '  .evil = .{ .url = "https://evil.example/x.tar.gz", .hash = "z" },\n'
        " },\n}\n")).dependencies
    assert deps[0].remote == "evil.example"
    by = _by_name("dub.json", '{"dependencies": {"vibe-d": "~>1.0",'
                             ' "evil": {"path": "../evil"}}}')
    assert by["vibe-d"].source_kind == "registry"
    assert by["evil"].source_kind == "path"
    by = _by_name("mypkg.nimble", 'requires "nim >= 1.6"\nrequires "jester >= 0.5"\n')
    assert {"nim", "jester"} <= set(by)
    by = _by_name("mypkg-1.0-1.rockspec",
                  'dependencies = { "lua >= 5.1", "luasocket >= 3.0" }')
    assert {"lua", "luasocket"} <= set(by)


def test_clojure_dune_rebar():
    by = _by_name("deps.edn", (
        '{:deps {org.clojure/clojure {:mvn/version "1.11.1"}\n'
        '        evil/evil {:git/url "https://evil.example/ev" :sha "x"}}}'))
    assert by["evil/evil"].remote == "evil.example"
    by = _by_name("project.clj", (
        '(defproject x "1" :dependencies [[org.clojure/clojure "1.11.1"]])'))
    assert "org.clojure/clojure" in by
    by = _by_name("dune-project",
                  "(package (name x) (depends ocaml dune lwt))\n")
    assert {"ocaml", "dune", "lwt"} <= set(by)
    by = _by_name("rebar.config", '{deps, [{cowboy, "2.9.0"}]}.')
    assert by["cowboy"].constraint == "2.9.0"


def test_cartfile_cabal_project_and_stack():
    by = _by_name("Cartfile", (
        'github "user/repo" "1.0"\ngit "https://evil.example/ev" "2.0"\n'))
    assert by["repo"].remote == "github.com"
    assert any(d.remote == "evil.example" for d in by.values())
    by = _by_name("cabal.project", (
        "packages: .\nsource-repository-package\n  location: https://evil.example/ev\n"
        "  tag: abc\n"))
    assert any(d.remote == "evil.example" for d in by.values())
    by = _by_name("stack.yaml", (
        "resolver: lts-21.0\nextra-deps:\n  - aeson-2.1.0.0\n"
        "  - git: https://evil.example/ev\n    commit: abc\n"))
    assert any(d.remote == "evil.example" for d in by.values())
    by = _by_name("package.yaml", "dependencies:\n  - base >=4.14\n  - text\n")
    assert {"base", "text"} <= set(by)


def test_cmake_meson_bazel_perl_meta():
    by = _by_name("CMakeLists.txt", (
        "FetchContent_Declare(evil\n"
        "  GIT_REPOSITORY https://evil.example/ev\n)\n"))
    assert any(d.remote == "evil.example" for d in by.values())
    by = _by_name("meson.build", "x = dependency('zlib', version: '>=1.0')\n")
    assert "zlib" in by
    by = _by_name("MODULE.bazel",
                  'bazel_dep(name = "rules_go", version = "0.42")\n')
    assert by["rules_go"].constraint == "0.42"
    by = _by_name("META.json", (
        '{"prereqs": {"runtime": {"requires": {"Moo": "0"}}}}'))
    assert "Moo" in by
