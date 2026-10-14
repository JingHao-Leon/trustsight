"""Extracted from delivery.py: _transitions."""

import re
from ...config import (
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines
from ._common import _VCS_SOURCE_RE, _source_basename

__all__ = ['_FLOATING_PATH_RE', '_SOURCE_ARRAY_NAME_RE', '_URL_HOST_RE', '_pinning_of', '_recipe_states', '_registered_domain_of', '_source_urls_by_local_name', 'install_hook_transition', 'pinning_lost', 'source_name_host_swaps']

_SOURCE_ARRAY_NAME_RE = re.compile(r"^source(?:_[a-z0-9_]+)?$")

_URL_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/'\"]+)")

def _recipe_states(diff_text: str):
    """The ``(pre, post)`` RecipeDocs of what the diff shows."""
    from ...recipedoc import recipe_states

    return recipe_states(parse_diff_lines(split_lines(diff_text)))

def _source_urls_by_local_name(recipe) -> dict[str, tuple[str, object | None]]:
    """``local name -> (url, span)`` for every ``source*`` array resolved.

    The local name is the ``name::url`` rename when present, else the URL's
    basename, which is what makepkg calls the downloaded file either way.
    Only http(s) entries key in: a bare local file has no host to swap.
    The span is the entry's line in the recipe's provenance, or None when
    the recipe was built without origins.
    """
    out: dict[str, tuple[str, object | None]] = {}
    for array, entries in recipe.arrays.items():
        if not _SOURCE_ARRAY_NAME_RE.match(array):
            continue
        spans = recipe.array_spans.get(array, ())
        for index, entry in enumerate(entries):
            # `source=("'git+https://…'")` carries the inner quotes as part
            # of the value; they are quoting, not part of the address.
            entry = entry.strip("\"'")
            name, sep, url = entry.partition("::")
            if not sep:
                url = name
                name = _source_basename(url)
            url = url.strip("\"'")
            # A VCS transport without `://` (`bzr+lp:user/proj`) is still
            # a source entry the pinning rules compare; only a bare local
            # file has no address to swap.
            if not name or not (_URL_HOST_RE.match(url)
                                or _VCS_SOURCE_RE.match(url)):
                continue
            span = spans[index] if index < len(spans) else None
            # Last occurrence wins: a diff fragment can show a name twice,
            # and the one that changed is the later one.
            out[name] = (url, span)
    return out

def _registered_domain_of(url: str) -> str:
    host = _URL_HOST_RE.match(url)
    if not host:
        return ""
    from ..structural import _registered_domain

    return _registered_domain(host.group(1))

def source_name_host_swaps(
    diff_text: str,
) -> list[tuple[str, str, str, str, str, object | None]]:
    """``(local name, old host, new host, old domain, new domain, span)``.

    H099's shape: the name survived but the registered domain moved.
    makepkg's source cache keys on the local name, so renaming the server
    under a kept name refetches nothing a reviewer would recognise as new:
    the quiet-swap attack.  Only names visible on both sides of the diff
    compare, so a partially shown array cannot pair a name with the wrong
    URL.  The span is the new entry's line.
    """
    pre, post = _recipe_states(diff_text)
    old = _source_urls_by_local_name(pre)
    new = _source_urls_by_local_name(post)
    swaps: list[tuple[str, str, str, str, str, object | None]] = []
    for name in sorted(set(old) & set(new)):
        old_url = old[name][0]
        new_url, new_span = new[name]
        if old_url == new_url:
            continue
        old_host_m, new_host_m = _URL_HOST_RE.match(old_url), _URL_HOST_RE.match(new_url)
        old_host = old_host_m.group(1) if old_host_m else ""
        new_host = new_host_m.group(1) if new_host_m else ""
        old_dom = _registered_domain_of(old_url)
        new_dom = _registered_domain_of(new_url)
        if old_dom and new_dom and old_dom != new_dom:
            swaps.append((name, old_host, new_host, old_dom, new_dom, new_span))
    return swaps

def install_hook_transition(
    diff_text: str,
) -> tuple[str, str, bool, object | None]:
    """``(old install=, new install=, hook script in this diff, span)``.

    H100's shape: an ``install=`` scalar appearing or retargeting hands
    root to a hook that was not there before; H017 inspects hook
    *content*, nothing watched the declaration itself.  The span is the
    declaration's own line.
    """
    pre, post = _recipe_states(diff_text)
    old_hook = pre.scalars.get("install", "")
    new_hook = post.scalars.get("install", "")
    doc = parse_diff_lines(split_lines(diff_text))
    hook_in_diff = any(
        f.path.endswith(".install") and f.status != "removed"
        for f in doc.files
    )
    return old_hook, new_hook, hook_in_diff, post.scalar_spans.get("install")

_FLOATING_PATH_RE = re.compile(r"/(?:latest|HEAD)(?:/|$)")

def _pinning_of(url: str) -> str:
    """``"pinned"`` or ``"floating"`` for one source URL (H101).

    A VCS entry is pinned by a `#commit=` fragment and floating on a
    branch ref, a tag, HEAD, or no fragment at all: a tag is a movable ref,
    and force-moving one is the classic supply-chain attack.  A plain
    archive URL is floating only when it names a moving target
    (`/latest/`, `/HEAD`); every other archive carries its version in the
    path by convention.
    """
    fragment = url.split("#", 1)[1] if "#" in url else ""
    # Any `transport+address` spelling (`git+`, `hg+`, `bzr+lp:`) is a VCS
    # fetch: floating without a commit fragment, whatever the transport.
    if re.match(r"\w+\+", url) or url.startswith("git://") or fragment:
        if fragment.startswith("commit="):
            return "pinned"
        return "floating"
    if _FLOATING_PATH_RE.search(url):
        return "floating"
    return "pinned"

def pinning_lost(
    diff_text: str,
) -> list[tuple[str, str, str, object | None, bool]]:
    """``(local name, old url, new url, span, renamed)`` where an entry went
    pinned to floating (H101).

    P008 flags a floating source wherever it stands; the transition rule
    catches the moment a verifiable package becomes upstream-controlled,
    which in a watch replay is the signal that matters.  Only same-name
    entries on both sides compare, the H099 keying.  *renamed* is True when
    the local name itself changed - a pinned tarball replaced by a floating
    VCS entry under a new name, a stronger loss than a pin moving in place.
    """
    pre, post = _recipe_states(diff_text)
    old = _source_urls_by_local_name(pre)
    new = _source_urls_by_local_name(post)
    lost: list[tuple[str, str, str, object | None, bool]] = []
    for name in sorted(set(old) & set(new)):
        old_url = old[name][0]
        new_url, new_span = new[name]
        if old_url == new_url:
            continue
        if _pinning_of(old_url) == "pinned" and _pinning_of(new_url) == "floating":
            lost.append((name, old_url, new_url, new_span, False))
    if lost:
        return lost
    # A rename carries the same lost pinning under a new local name: the
    # pinned `v1.0.0.tar.gz` is deleted and a floating
    # `git+https://…/repo.git` appears in its place.  Comparing only
    # same-name entries let that swap score nothing.
    gone_pinned = [n for n in old
                   if n not in new and _pinning_of(old[n][0]) == "pinned"]
    new_floating = [n for n in new
                    if n not in old and _pinning_of(new[n][0]) == "floating"]
    if gone_pinned and new_floating:
        old_name = gone_pinned[0]
        new_name = new_floating[0]
        lost.append((new_name, old[old_name][0],
                     new[new_name][0], new[new_name][1], True))
    return lost
