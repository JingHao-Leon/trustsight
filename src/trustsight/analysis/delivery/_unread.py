"""Extracted from delivery.py: _unread."""

import os
import re
from ...config import (
    EXEC_WRAPPER as _EXEC_WRAPPER,
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...deps import _strip_comment
from ...rules import (
    ScopeResolver,
)
from ...tokenizer import resolve_added_lines
from ..build import (
    _INSTALL_HOOKS,
    _recipe_lines,
)
from ._common import _BUILD_FUNCTIONS, _BUILD_ONLY_PATH_RE, _CMD_START, _DESCRIPTIVE_FIELD_RE, _PATCH_APPLY_RE, _SCOPE_FUNCTIONS, _declared_source_basenames, _find_line, _heredoc_body_indices, _norm_path, _not_a_path

__all__ = ['_BOOT_ARTIFACT_RE', '_CONTENT_WRITE_RE', '_COPY_SOURCE_RE', '_FD_REDIRECT_RE', '_MAKE_TARGET_RE', '_MANIFEST_ARG_RE', '_PACKAGING_FUNCTIONS', '_PATCH_APPLY_RUNTIME_RE', '_PKGDIR_TARGET_RE', '_QUOTED_SEGMENT_RE', '_SANDBOX_WRAPPER_RE', '_STANDARD_TARGETS', '_W001_RE', '_generated_config_findings', '_unread_manifest_findings', '_unread_patch_findings', '_unread_target_findings', '_unverifiable_findings']

_PACKAGING_FUNCTIONS = frozenset({"package"}) | frozenset(_INSTALL_HOOKS)

_CONTENT_WRITE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:printf|echo|tee|cat)\b",
)

_PKGDIR_TARGET_RE = re.compile(r"\$\{?pkgdir\}?")

_W001_RE = re.compile(
    # Two shapes, and no third. An interpreter naming a file, or a `./`
    # invocation - both are unambiguously "run this". A bare path-shaped
    # word at a command position is not: that reading matched the MIME
    # type in `x-scheme-handler/orcaslicer`, the `usr/bin/env` of a
    # shebang line and the innards of `sed 's/-/./g'`.
    _CMD_START
    + r"(?:"
    # `/bin/sh` and `/usr/bin/python3` are the same executors spelled by
    # path, and a sandbox wrapper almost always spells them that way:
    # `chroot "$srcdir/root" /bin/sh /x.sh` ran an unread script and
    # matched nothing, because the arm wanted a bare word.
    # The whole command may be one quoted argument: `xterm -e "bash
    # $PWD/x.sh"` puts the executor inside the quotes, not the path.
    r"[\"']?(?:/(?:usr/)?bin/)?"
    r"(?:bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|node|php|lua(?:jit)?"
    r"|tclsh|wish|julia|Rscript|bun|deno)\s+"
        # `$PWD` is the build directory under another name, and a recipe that
    # runs `$PWD/x.sh` is running tree content exactly as `$srcdir/x.sh`
    # does.
    r"[\"']?((?:\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/|\./|[\w.-]+/)[\w./-]+"
    r"|[\w.-]+\.(?:sh|bash|py|pl|rb|js|lua|php|tcl|jl|R|ts))"
    r"|\./([\w.-]+(?:/[\w.-]+)*)"
    # A sandbox wrapper establishes a new root, so an *absolute* path after
    # it is a path inside that root - which is tree content, not a system
    # file. `chroot "$srcdir/root" /bin/sh /x.sh` runs a script from the
    # unpacked tree and names it `/x.sh`; without this arm the leading
    # slash made it look like `/usr/bin/foo.sh`, which is not this rule's
    # subject at all.
    r"|(?<=\s)(/[\w.-]+(?:/[\w.-]+)*\.(?:sh|bash|py|pl|rb|js|lua|php|tcl|jl|R|ts))"
    r")[\"']?(?:\s|;|$)",
    re.IGNORECASE,
)

_SANDBOX_WRAPPER_RE = re.compile(
    r"\b(?:chroot|bwrap|firejail|nsjail|unshare|proot|fakechroot"
    r"|systemd-nspawn|toolbox|distrobox-enter)\b",
    re.IGNORECASE,
)

_PATCH_APPLY_RUNTIME_RE = re.compile(
    _CMD_START + r"(?:patch|git\s+apply)\b[^\n;&|]*?"
    r"(?:<\s*|--input[=\s]+|-i\s+)[\"']?([^\"'\s;&|<>]+)[\"']?",
    re.IGNORECASE,
)

_MANIFEST_ARG_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu|bazel|buck2?|pants|scons|waf|just|task)\b"
    r"[^\n;&|]*?\s-(?:f|-file|-makefile)[=\s]+[\"']?"
    r"([^\"'\s;&|]+)",
    re.IGNORECASE,
)

def _unread_manifest_findings(diff_text, add, tree_manifest=None,
                              current_text=None) -> None:
    """A build engine run against steps nobody read (W004).

    The counterpart to X020. That rule claims the recipe *writing* a
    manifest; this one reports the recipe *pointing an engine at* one whose
    content is neither declared nor committed. H083 already claims the case
    where the named file is a declared source - there the bytes are at
    least checksum-pinned - so what is left is a manifest that arrived
    inside an archive, and whose build steps are therefore chosen by
    something this analysis never saw.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    source_basenames = _declared_source_basenames(diff_text, current_text)
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _MANIFEST_ARG_RE.search(body)
        if not m:
            continue
        raw = m.group(1)
        if _not_a_path(raw):
            continue
        base = os.path.basename(_norm_path(raw))
        if not base or base in source_basenames or base in committed:
            continue
        add("W004", "Build Engine Runs A Manifest This Analysis Did Not Read",
            "INFO", "unverifiable",
            f"{fn}() points a build engine at {raw}, whose steps are neither "
            "declared in source=() nor committed to this repository",
            line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
        return

_STANDARD_TARGETS = frozenset({
    "all", "install", "install-strip", "clean", "distclean", "mostlyclean",
    "check", "test", "tests", "dist", "world", "modules", "modules_install",
    "defconfig", "menuconfig", "oldconfig", "prepare", "build", "docs",
    "doc", "man", "html", "info", "uninstall", "release", "debug",
})

_MAKE_TARGET_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|ninja|samu)\b([^\n;&|#]*)",
    re.IGNORECASE,
)

def _unread_target_findings(diff_text, add, tree_manifest=None,
                            current_text=None) -> None:
    """A build target whose recipe nobody read (W005).

    The third of the manifest trio. X020 claims the recipe *writing* the
    steps, W004 the recipe naming a manifest file, and this one the recipe
    naming a *target* inside a manifest it did not name - the implicit
    `Makefile` that came with the archive.

    Standard targets stand down. `make install` is a contract every build
    system honours and says what it does; `make dist-hooks` names a recipe
    that exists only in this project's Makefile.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    if committed & {"Makefile", "makefile", "GNUmakefile", "build.ninja"}:
        return
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _MAKE_TARGET_RE.search(body)
        if not m:
            continue
        for token in m.group(1).split():
            # Flags and variable assignments are not targets.
            if token.startswith("-") or "=" in token:
                continue
            if token.lower() in _STANDARD_TARGETS:
                continue
            if _not_a_path(token) or "/" in token:
                continue
            add("W005", "Build Runs A Target Whose Recipe Was Not Read",
                "INFO", "unverifiable",
                f"{fn}() runs the {token!r} target, whose recipe is in a "
                "build file that arrived with the source and was never read",
                line=_find_line(diff_text, body.strip()[:50]),
                position=fn, target=token)
            return

_BOOT_ARTIFACT_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:dracut|mkinitcpio|update-initramfs|grub2?-mkconfig|grub2?-install"
    r"|guestfish|virt-customize|virt-sysprep|bootctl)\b([^\n;&|]*)",
    re.IGNORECASE,
)

_FD_REDIRECT_RE = re.compile(r"\A&\d")

_QUOTED_SEGMENT_RE = re.compile(r"\"([^\"]*)\"|'([^']*)'")

_COPY_SOURCE_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)cat\s+[\"']?\$\{?(?:srcdir|startdir)\}?/")

def _generated_config_findings(diff_text, add, current_text=None) -> None:
    """A generated file whose body names a build-tree path (W006).

    X022 claims this when the recipe goes on to hand the file to a tool.
    Without that second line there is no evidence anything reads it - the
    file may be a build input, a generated `.pc`, a note. What can be said
    is narrower and still worth saying: the recipe wrote a file whose
    content names a directory that exists only during the build, and
    whether anything runs it is not visible here.

    That is a W and not a rule with weight, because the claim stops at
    "unreadable", and the same predicate H093 uses decides it: a line that
    names a build-only path and is not a field that merely describes.
    """
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _SCOPE_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        if not _CONTENT_WRITE_RE.search(body) or _COPY_SOURCE_RE.search(body):
            continue
        cut = body.rfind(">")
        if cut < 0 or _FD_REDIRECT_RE.match(body[cut + 1:]):
            continue
        content, target = body[:cut], body[cut + 1:]
        if _PKGDIR_TARGET_RE.search(target):
            continue          # H089 owns anything staged into the package.
        named = _BUILD_ONLY_PATH_RE.search(content)
        if named is None:
            continue
        # The descriptive test reads the *written text*, not the shell
        # line. `printf "Comment=built in $srcdir\n" > f` starts with
        # `printf`, so anchoring on the line missed the field entirely and
        # claimed a tidy-up note as a config directive.
        if any(_DESCRIPTIVE_FIELD_RE.search(a or b)
               for a, b in _QUOTED_SEGMENT_RE.findall(content)):
            continue
        add("W006", "Generated File Names A Build-Only Path", "INFO",
            "unverifiable",
            f"{fn}() writes a file whose content names {named.group(0)}; "
            "whether anything reads it is not visible here",
            line=_find_line(diff_text, body.strip()[:50]),
            position=fn, path=named.group(0))
        return

def _unverifiable_findings(diff_text, config, add, tree_manifest=None,
                           current_text=None, ctx=None) -> None:
    """The W series: what ran, or will run, that nobody here read."""
    from ..edges import build_context, run_edge_instances

    if ctx is None:
        ctx = build_context(diff_text, config, current_text=current_text,
                            tree_manifest=tree_manifest)
    run_edge_instances(ctx, add, only=frozenset({"H094"}))

    from ..buildfetch import registry_resolutions

    resolutions = registry_resolutions(diff_text, current_text)
    if resolutions:
        function, command = resolutions[0]
        others = len(resolutions) - 1
        suffix = f" (and {others} more)" if others else ""
        # Cross-reference the committed manifest surface (U-series): the gap
        # never reads the same with and without a committed manifest.
        from ..upstream_manifests import committed_manifest, ecosystem_of_command

        committed = committed_manifest(tree_manifest, command)
        if committed:
            fmt, path = committed
            tail = (f"; the {fmt} dependency surface is committed ({path}) "
                    "and was analyzed, but the registry resolution at build "
                    "time remains unseen")
        else:
            fmt = ecosystem_of_command(command)
            tail = (f"; no committed {fmt} manifest names that surface"
                    if fmt else "")
        add("W002", "Build Resolves Dependencies From A Registry", "INFO",
            "unverifiable",
            f"{function or 'the recipe'} runs {command.strip()[:60]}, so a "
            "registry chooses at build time which code runs; no checksum "
            f"here covers it{suffix}{tail}",
            line=_find_line(diff_text, command.strip()[:50]),
            position=function, command=command.strip()[:80],
            count=len(resolutions))

    _unread_patch_findings(diff_text, add, tree_manifest=tree_manifest,
                           current_text=current_text)
    _unread_manifest_findings(diff_text, add, tree_manifest=tree_manifest,
                              current_text=current_text)
    _unread_target_findings(diff_text, add, tree_manifest=tree_manifest,
                            current_text=current_text)
    _generated_config_findings(diff_text, add, current_text=current_text)

def _unread_patch_findings(diff_text, add, tree_manifest=None,
                           current_text=None) -> None:
    """A patch applied from bytes this analysis never read (W003)."""
    lines = resolve_added_lines(diff_text)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    committed = {os.path.basename(name.rstrip("/"))
                 for name, _head in (tree_manifest or ())}
    heredoc_body = _heredoc_body_indices(lines)

    for i, line in enumerate(lines):
        fn = scopes.within(i, _BUILD_FUNCTIONS)
        if not line.startswith("+") or fn is None or i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        m = _PATCH_APPLY_RE.search(body)
        if m:
            raw = m.group(1)
            if _not_a_path(raw):
                continue
            base = os.path.basename(_norm_path(raw))
            # A committed patch is one H090 has already read.
            if not base or base in committed:
                continue
        else:
            # The target is named at runtime (a variable or a glob): the
            # basename cannot be compared against the tree.  When the tree
            # commits any patch, a glob or loop over "$srcdir"/*.patch is
            # most likely reading those, which H090 has already read;
            # otherwise the applied bytes are genuinely unread.
            m = _PATCH_APPLY_RUNTIME_RE.search(body)
            if not m:
                continue
            raw = m.group(1)
            if not raw:
                continue
            if any(b.endswith((".patch", ".diff")) for b in committed):
                continue
            base = raw
        add("W003", "Applies A Patch This Analysis Did Not Read", "INFO",
            "unverifiable",
            f"{fn}() applies {base}, whose content is not in this repository "
            "and was never read",
            line=_find_line(diff_text, raw[:60]), position=fn, path=raw)
        return
