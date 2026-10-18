"""Verified baseline and IOC pulls, shared by the CLI and the watcher.

``seed fetch``, ``corpus fetch``, ``ioc update`` and the watcher's
``--auto-pull-*`` options all do the same three things: download a signed
asset from a release channel (or a publisher's federation directory), verify
its detached ed25519 signature against the channel's pinned key, and import
the result.  This module is that path once, so an auto-pull from an unattended
watcher is byte-for-byte the same verified import an operator gets by hand -
never a second, weaker code path.

Nothing here draws anything or decides policy; the caller prints and records.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from . import channel_state, release

log = logging.getLogger(__name__)

#: A feed's ``asset``/``name`` becomes part of an asset name.
_ASSET_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")

#: A tag becomes a URL path segment; refused unless it is a safe one.
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: The seed asset pulled by ``--auto-pull-baselines`` and ``seed fetch``.
SEED_ASSET_NAME = "baseline-seed.tar.gz"

#: The corpus baseline asset.
CORPUS_ASSET_NAME = "baseline-corpus.tar.zst"

#: A progress factory: given a description, a context manager yielding an
#: ``on_progress(pos, total)`` callback.  The CLI passes a Rich factory; the
#: watcher passes nothing (no terminal to draw on).
ProgressFactory = Callable[[str], object]


def channel_key_fingerprint(channel: release.Channel) -> str | None:
    """``sha256:<hex16>`` of a channel's raw pinned key, or ``None``.

    The key material itself is never logged or shown; the fingerprint is
    enough to tell two publishers apart, matching the convention in
    ``docs/reference/baseline-keys.md``.
    """
    try:
        if channel.key_bytes is not None:
            raw = channel.key_bytes
        elif channel.key_path is not None:
            raw = Path(channel.key_path).read_bytes()
        else:
            return None
    except OSError:
        return None
    if len(raw) != 32:
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def non_official_warning(channel: release.Channel) -> str | None:
    """The stderr warning for a non-official channel, or ``None``.

    Following a channel other than the shipped one means trusting whoever
    publishes it; every import from one says so, once.
    """
    if channel.official:
        return None
    fingerprint = channel_key_fingerprint(channel)
    where = f" (key {fingerprint})" if fingerprint else ""
    return (
        f"trustsight: WARNING: importing from the non-official release channel "
        f"'{channel.label}'{where}. You are trusting that publisher; the "
        f"official channel is '{release.OFFICIAL_REPO}'."
    )


def publisher_warning(label: str) -> str:
    """The stderr warning for a non-official federation publisher."""
    return (
        f"trustsight: WARNING: importing IOCs from the non-official publisher "
        f"'{label}'. You are trusting that publisher; the official channel is "
        f"'{release.OFFICIAL_REPO}'."
    )


def _emit_warning(channel: release.Channel) -> None:
    message = non_official_warning(channel)
    if message:
        print(message, file=sys.stderr)


def _verified_download(asset_name: str, *, tag: str | None,
                       channel: release.Channel,
                       progress: ProgressFactory | None,
                       pubkey_path: Path | None = None) -> bytes:
    if progress is None:
        return release.fetch_verified_asset(
            asset_name, tag=tag, channel=channel, pubkey_path=pubkey_path
        )
    ctx = progress(f"Downloading {asset_name}...")
    with ctx as on_download:
        return release.fetch_verified_asset(
            asset_name, tag=tag, channel=channel, on_progress=on_download,
            pubkey_path=pubkey_path,
        )


def pull_baseline_seed(
    channel: release.Channel | None = None,
    tag: str | None = None,
    progress: ProgressFactory | None = None,
    pubkey_path: Path | None = None,
) -> dict:
    """Pull, verify and import the novelty seed, recording the pull.

    Raises a ``release.ReleaseError`` subclass on any refusal.  Returns the
    import stats plus ``tag``/``url``/``channel``.
    """
    from .db import import_seed

    channel = channel or release.active_baseline_channel()
    _emit_warning(channel)
    data = _verified_download(
        SEED_ASSET_NAME, tag=tag, channel=channel, progress=progress,
        pubkey_path=pubkey_path,
    )
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-fetch-"))
    try:
        path = tmp_dir / SEED_ASSET_NAME
        path.write_bytes(data)
        stats = import_seed(path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    url = release.asset_url(SEED_ASSET_NAME, tag, channel)
    channel_state.record_pull(
        channel_state.BASELINE, release.tag_from_asset_url(url), channel.repo
    )
    return {"tag": tag or "latest", "url": url, "channel": channel.repo, **stats}


def _release_channel_feed(feed: dict, prefix: str,
                          progress: ProgressFactory | None) -> dict:
    """Update one feed from a followed release channel (the channel flow)."""
    from .ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    channel = release.channel_for_url(feed.get("url") or "")
    assert channel is not None  # caller checked
    # Every import from a non-official channel says so, before anything is
    # downloaded or imported.
    _emit_warning(channel)
    tag_value = feed.get("tag")
    tag = str(tag_value).strip() if tag_value is not None else ""
    if tag and not _TAG_RE.match(tag):
        return {"status": "error",
                "error": f"invalid release tag {tag!r}; use [A-Za-z0-9._-]"}
    tag = tag or None
    manifest_asset = f"baseline-ioc-{prefix}-manifest.json"
    iocs_asset = f"baseline-ioc-{prefix}-iocs.jsonl"
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-fetch-"))
    try:
        (tmp_dir / "manifest.json").write_bytes(
            _verified_download(manifest_asset, tag=tag, channel=channel,
                               progress=progress)
        )
        (tmp_dir / "iocs.jsonl").write_bytes(
            _verified_download(iocs_asset, tag=tag, channel=channel,
                               progress=progress)
        )
        result = import_baseline(tmp_dir, source_name=feed.get("name") or "",
                                 trust_manifest_key=True)
        url = release.asset_url(manifest_asset, tag, channel)
        channel_state.record_pull(
            channel_state.IOC, release.tag_from_asset_url(url), channel.repo
        )
        return {"status": "ok", "url": url, "channel": channel.repo, **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _federation_feed(feed: dict, url: str,
                     progress: ProgressFactory | None) -> dict:
    """Update one feed from a publisher's signed directory (federation)."""
    from .ioc_baseline import (
        InvalidSignatureError,
        MalformedBaselineError,
        UnsignedBaselineError,
        import_baseline,
    )

    key_value = str(feed.get("key") or "").strip()
    if not key_value:
        return {
            "status": "error",
            "error": (
                "a non-release feed URL needs a pinned publisher key: set "
                "`key` to the publisher's ed25519 public key"
            ),
        }
    key_path = Path(key_value)
    label = url.rstrip("/")
    print(publisher_warning(label), file=sys.stderr)
    tmp_dir = Path(tempfile.mkdtemp(prefix="trustsight-ioc-federation-"))
    try:
        # fetch_verified_url has no progress hook; the federation directory is
        # small (a manifest plus an indicator list), so a bar is not missed.
        for asset in ("manifest.json", "iocs.jsonl"):
            (tmp_dir / asset).write_bytes(
                release.fetch_verified_url(url, asset, pubkey_path=key_path)
            )
        result = import_baseline(tmp_dir, source_name=label,
                                 trust_manifest_key=True)
        return {"status": "ok", "url": label, **result}
    except (release.ReleaseError, UnsignedBaselineError, InvalidSignatureError,
            MalformedBaselineError, FileNotFoundError) as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def pull_ioc_feed(feed: dict, progress: ProgressFactory | None = None) -> dict:
    """Pull, verify and import one configured IOC feed.

    Two shapes are accepted:

    * a followed release channel (the official one, or the configured
      ``[release] channel``), whose ``baseline-ioc-<prefix>-*`` pair is
      resolved from the newest ``ioc-*`` release; and
    * any other ``http(s)`` URL, treated as a publisher's federation directory
      (``manifest.json`` + ``iocs.jsonl``) whose detached signatures must
      verify against the feed's own pinned ``key``.

    A refusal is returned as ``{"status": "error", ...}``; nothing raises.
    """
    name = feed.get("name") or ""
    url = feed.get("url") or ""
    prefix = feed.get("asset") or name

    result: dict
    if release.channel_for_url(url) is not None:
        if not prefix or not _ASSET_PREFIX_RE.match(prefix):
            return {"status": "error",
                    "error": f"invalid asset prefix {prefix!r}; use [a-z0-9.-]"}
        result = _release_channel_feed(feed, prefix, progress)
    elif url.startswith("https://") or url.startswith("http://"):
        result = _federation_feed(feed, url, progress)
    else:
        result = {
            "status": "error",
            "error": (
                "unsupported feed URL; use a followed release channel or an "
                "https:// publisher directory (use 'ioc import <dir>' for "
                "local baselines)"
            ),
        }
    return {"feed": name, **result}


def enabled_feeds() -> list[dict]:
    """The operator's enabled IOC feeds, from ``[baselines.ioc]``."""
    from .config import load_config

    try:
        section = load_config().get("baselines", {}).get("ioc", {})
    except Exception:  # noqa: BLE001 - an unreadable config means no feeds
        return []
    if not bool(section.get("enabled", True)):
        return []
    feeds = section.get("feeds", [])
    return [f for f in feeds if isinstance(f, dict) and f.get("enabled", True)]


def auto_pull(*, baselines: bool = False, iocs: bool = False) -> list[str]:
    """Pull a newer baseline seed and/or IOC feeds, once each, best-effort.

    Called by the watcher after every cycle.  Only pulls when the channel
    offers a tag the operator has not already pulled (recorded in
    :mod:`trustsight.channel_state`), so a quiet cycle costs one metadata
    query, not a re-download.  Returns human-readable summary lines; it never
    raises, because a failed data pull must not kill the watch.
    """
    notes: list[str] = []
    if not (baselines or iocs):
        return notes
    # A watcher process runs for weeks; the per-process tag cache would pin it
    # to the first tag it ever saw.  Re-query every cycle.
    release.clear_tag_cache()
    if baselines:
        try:
            channel = release.active_baseline_channel()
            newest = release.resolve_baseline_tag(channel)
            if newest and newest != channel_state.pulled_tag(channel_state.BASELINE):
                stats = pull_baseline_seed(channel=channel)
                notes.append(
                    f"baseline seed pulled: {stats['tag']} ({stats['channel']})"
                )
        except Exception as exc:  # noqa: BLE001 - never kill the watch
            notes.append(f"baseline auto-pull skipped: {exc}")
    if iocs:
        try:
            newest = release.resolve_ioc_tag()
        except Exception as exc:  # noqa: BLE001
            newest = None
            notes.append(f"ioc auto-pull skipped: {exc}")
        if newest and newest != channel_state.pulled_tag(channel_state.IOC):
            for feed in enabled_feeds():
                name = feed.get("name") or "(unnamed)"
                result = pull_ioc_feed(feed)
                if result.get("status") == "ok":
                    notes.append(
                        f"iocs pulled for {name}: "
                        f"{result.get('entries_imported', 0)} entries"
                    )
                else:
                    notes.append(
                        f"iocs auto-pull skipped for {name}: {result.get('error')}"
                    )
    return notes
