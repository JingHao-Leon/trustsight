"""The operator watchlist: hand-curated accounts and packages.

Registration date, "Inactive since" and suspension state live on AUR profile
pages, and the pipeline reads only RPC metadata, so no machine rule can compute
them.  Where a human has established such a fact - the pattern Claudia triages
by hand, ``Inactive-since ~ Last Updated and Last Packager = Package
Maintainer`` - this list records it, and a package whose maintainer is listed is
reported as **G009 Watchlisted Subject** (weight 0) rather than silently
trusted.  A package can be listed directly for the same reason: the operator
wants it named in the report.

Maintainer entries are keyed by the same salted SHA-256 the
``maintainers_hashed`` table uses (:func:`trustsight.db._hash_maintainer_value`),
so no plaintext identity is retained.  The salt is per-installation, so an entry
only ever matches on the installation that added it - which is where the
operator's judgement applies.  Package names are already public in every record,
report and AUR page, so they are stored as written.

The file lives beside the other operator configuration::

    ~/.config/trustsight/watchlist.json

and is absent by default, so G009 is silent on a clean install.  Add a
maintainer with the local salt, or a package without one::

    python -c "from trustsight.watchlist import add_entry; add_entry('fennekuiper', 'June 2026 orphan sweep')"
    python -c "from trustsight.watchlist import add_package; add_package('xsp', 'June 2026 review')"
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["add_entry", "add_package", "default_path", "load_packages",
           "load_watchlist", "local_hash", "watchlist_hashes"]


def default_path() -> Path:
    """The watchlist's default location, beside the operator's other config."""
    from .config import CONFIG_DIR

    return CONFIG_DIR / "watchlist.json"


def _read(path) -> dict:
    target = Path(path) if path else default_path()
    try:
        data = json.loads(target.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_watchlist(path=None) -> dict[str, str]:
    """Return ``{name_hash: label}`` for the watchlist, empty when absent.

    An unreadable or malformed file is empty, never an error: a watchlist is an
    optional operator aid and must not break an analysis.
    """
    out: dict[str, str] = {}
    for entry in _read(path).get("entries") or ():
        if not isinstance(entry, dict):
            continue
        name_hash = str(entry.get("name_hash", "")).strip()
        if name_hash:
            out[name_hash] = str(entry.get("label", "") or "")
    return out


def watchlist_hashes(path=None) -> set[str]:
    """The set of watchlisted name hashes."""
    return set(load_watchlist(path))


def load_packages(path=None) -> dict[str, str]:
    """Return ``{package: label}`` for the watchlist's package entries.

    Package names are public, so they are stored as written rather than
    hashed.  A missing or malformed section is empty, never an error: the
    watchlist is an optional operator aid and must not break an analysis.
    """
    packages = _read(path).get("packages")
    if not isinstance(packages, dict):
        return {}
    out: dict[str, str] = {}
    for name, label in packages.items():
        package = str(name).strip()
        if package:
            out[package] = str(label or "")
    return out


def local_hash(name: str) -> str | None:
    """The name's hash under this installation's salt, or None if unseeded."""
    from .db import get_connection
    from .db._connection import _get_salt, _hash_maintainer_value

    if not name.strip():
        return None
    with get_connection() as conn:
        salt = _get_salt(conn)
    if not salt:
        return None
    return _hash_maintainer_value(name, salt)


def add_entry(name: str, label: str = "", path=None) -> str:
    """Add *name* to the watchlist and return its stored hash.

    The name is hashed with this installation's salt, so nothing plaintext is
    written.  Requires a seeded database: without a salt there is nothing the
    later lookup would match against.
    """
    name_hash = local_hash(name)
    if not name_hash:
        raise RuntimeError(
            "no maintainer salt is configured; seed or migrate the database "
            "before adding a watchlist entry"
        )
    target = Path(path) if path else default_path()
    data = _read(target)
    entries = [e for e in (data.get("entries") or ()) if isinstance(e, dict)]
    if not any(e.get("name_hash") == name_hash for e in entries):
        entries.append({"name_hash": name_hash, "label": label})
    data["version"] = 1
    data["entries"] = entries
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n")
    return name_hash


def add_package(name: str, label: str = "", path=None) -> str:
    """Add *name* to the watchlist's package entries and return it.

    Unlike :func:`add_entry`, no salted hash or seeded database is involved: a
    package name is already public in every record and report, so there is
    nothing to protect.
    """
    package = str(name).strip()
    if not package:
        raise ValueError("a watchlist package name cannot be empty")
    target = Path(path) if path else default_path()
    data = _read(target)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        packages = {}
    packages.setdefault(package, label)
    data["version"] = 1
    data["packages"] = packages
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n")
    return package
