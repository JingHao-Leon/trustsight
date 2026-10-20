"""G-series: cross-package correlation.

The only family whose input is the *set* of recent analyses, not one
package.  Mechanistically distinct from D (single-package graph walk) and T
(single-package history): G's input is collective, so it runs at cycle end
in the full-AUR sweep, never on a single ``review``.

Runs over a list of per-package correlation records (the corpus builder
supplies them), so the join logic is testable without a live corpus:

* **G001 Shared Gained Host** (HIGH): the same gained canonical host appears
  in at least N packages in the window.  A "new CDN" is plausible once,
  damning five times.
* **G002 Shared Added Literal** (HIGH): an identical added literal above a
  length floor appears in at least two unrelated packages.
* **G003 Coordinated Adoption** (MEDIUM, HIGH for a first-seen account
  adopting dormant targets): the same maintainer key adopted at least M
  packages in the window.
* **G008 First-Seen Account Adoption Burst** (HIGH): an account with no
  prior maintainer history adopts many dormant packages at once.  It reads
  the maintainer-event timeline, so it is a DB-backed rule invoked from the
  sweep beside G006, not from :func:`correlate`.
* **G009 Watchlisted Subject** (INFO, weight 0): a package named directly on
  the operator's hand-curated watchlist, or one whose maintainer is.  It is the
  sanctioned home for profile-page facts the RPC metadata does not carry, and
  for an operator's package-level attention.  Report-only.

Members are named in the finding; the roundup is one alert, not N.

Live coverage caveat: G001, G002, G003 and G005 have a connected corpus feed
today.  G004 (upstream dependencies) ships and is unit-tested, but the view
that would supply it is pending, so it cannot fire on a real ``full-aur``
cycle yet.  See the correlation rule reference.
"""

from __future__ import annotations

import time
from collections import defaultdict

__all__ = ["correlate", "shared_gained_host", "shared_added_literal",
           "coordinated_adoption", "shared_upstream_dependency",
           "first_seen_adoption_burst", "watchlisted_maintainer"]


def _thresholds(config) -> dict:
    return (config or {}).get("thresholds", {})


def _maintainer_first_seen_ts(maintainer: str):
    """Earliest recorded maintainer-event timestamp, or ``None``.

    A database read shared by the adoption rules.  Any read failure is
    ``None`` (``unknown``), never an established account, so a cold or
    unreadable database cannot manufacture novelty.
    """
    from ..db import maintainer_first_seen
    from ..db._history import _parse_ts

    try:
        first_seen = maintainer_first_seen(maintainer)
    except Exception:
        return None
    if not first_seen:
        return None
    try:
        return _parse_ts(first_seen).timestamp()
    except (ValueError, TypeError):
        return None


#: Buckets whose hosts are ubiquitous and carry no campaign signal: five
#: unrelated packages gaining `github.com` is not a shared-CDN campaign, it is
#: how the AUR works.
_UBIQUITOUS_BUCKETS = frozenset({"trusted_forge", "official"})


def shared_gained_host(records, min_packages: int = 5) -> list[dict]:
    """G001: a gained host shared by *min_packages* distinct packages.

    A host that is itself a trusted forge or official channel is skipped: the
    join only means something for a *new* host a set of packages did not all
    already reach through the ordinary sources.
    """
    from ..buckets import classify_url

    by_host: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for host in record.get("hosts_gained", ()) or ():
            if host:
                by_host[host].add(str(record.get("package", "")))
    out = []
    for host, members in sorted(by_host.items()):
        if len(members) < min_packages:
            continue
        bucket, _domain = classify_url(f"https://{host}")
        if bucket in _UBIQUITOUS_BUCKETS:
            continue
        out.append({
            "rule_id": "G001",
            "name": "Shared Gained Host",
            "severity": "HIGH", "category": "correlation",
            "match": (f"gained host {host} appears in {len(members)} "
                      "packages in the window"),
            "params": {"members": sorted(members), "host": host},
        })
    return out


def shared_added_literal(records, min_packages: int = 2,
                         min_length: int = 256) -> list[dict]:
    """G002: an identical added literal in *min_packages* packages."""
    by_literal: dict[str, set[str]] = defaultdict(set)
    for record in records:
        for literal in record.get("added_literals", ()) or ():
            text = str(literal)
            if len(text) >= min_length:
                by_literal[text].add(str(record.get("package", "")))
    out = []
    for literal, members in by_literal.items():
        if len(members) >= min_packages:
            out.append({
                "rule_id": "G002",
                "name": "Shared Added Literal",
                # Never print the literal's content: name its class only.
                "severity": "HIGH", "category": "correlation",
                "match": (f"an added literal of {len(literal)} chars appears "
                          f"in {len(members)} packages in the window"),
                "params": {"members": sorted(members),
                           "literal_length": len(literal)},
            })
    return out


def _one_related_cluster(members) -> bool:
    """True when every member name belongs to one relatedness cluster.

    Union-find over :func:`~trustsight.deps.is_related_package`: two names
    share an edge when either is a variant/companion/sibling of the other.
    A single cluster covering every member means the group is one project's
    naming family (``appattic``/``appattic-bin``/``appattic-qt``), which is
    H052's shape regardless of whether repo data exists yet.
    """
    from ..deps import is_related_package

    names = sorted(members)
    parent = {name: name for name in names}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if is_related_package(a, b):
                parent[find(a)] = find(b)
    return len({find(name) for name in names}) == 1


def coordinated_adoption(records, min_members: int = 3,
                         config=None) -> list[dict]:
    """G003: one maintainer key adopting *min_members* unrelated packages.

    Joins on the temporal adoption predicates (H044 ownership transition,
    H086 orphan-to-maintained) recorded per package, so the group is an
    adoption event the temporal engine would also fire - not a bare
    maintainer-change.

    The members must be **unrelated**: a maintainer adopting several packages
    that all source from one repository is a variant family (H052's shape),
    not a coordinated takeover.  When every member has repo data and they
    share a common repo, G003 stands down; any member without repo data keeps
    the group firing, because an unproven relationship is not evidence of one.

    New packages land in the window with no repo data yet, which used to make
    the repo test vacuous for exactly the case it exists for: a maintainer
    releasing ``appattic``, ``appattic-bin`` and ``appattic-qt`` in one cycle
    is the same variant family by name even where the corpus has not learned
    the repos.  A naming-relatedness pass (``is_related_package``) therefore
    stands the group down the same way: one cluster of related names is one
    project, not a campaign.

    Novelty/dormancy weighting (``[g003]``): a *globally novel* maintainer
    (its earliest recorded maintainer-event falls within ``novel_days``)
    adopting dormant targets (``last_modified`` older than ``dormant_days``)
    is the fennekuiper shape G008 exists for.  When it holds for at least
    ``min_dormant`` members the finding is escalated to HIGH; the bare
    N-adoption shape stays MEDIUM, so established maintainers keep the old
    posture.  The escalation changes the alert severity and evidence, not
    member scores - correlation clusters do not score their members
    (``_apply_cluster_weights`` skips every G finding but G005).
    """
    thresholds = _thresholds(config)
    g003 = thresholds.get("g003", {})
    novel_days = int(g003.get("novel_days", 30))
    min_dormant = int(g003.get("min_dormant", 2))
    dormant_days = int(g003.get("dormant_days", 180))
    now = time.time()
    novel_cutoff = now - novel_days * 86400
    dormant_cutoff = now - dormant_days * 86400

    by_maintainer: dict[str, set[str]] = defaultdict(set)
    predicates: dict[str, set[str]] = defaultdict(set)
    repos: dict[str, list[set[str]]] = defaultdict(list)
    last_modified: dict[str, list[float]] = defaultdict(list)
    for record in records:
        maintainer = str(record.get("maintainer", "") or "").strip().lower()
        if maintainer and record.get("adoption"):
            by_maintainer[maintainer].add(str(record.get("package", "")))
            predicates[maintainer] |= set(
                record.get("adoption_predicates") or ())
            repos[maintainer].append(set(record.get("source_repos") or ()))
            last_mod = record.get("last_modified")
            if isinstance(last_mod, (int, float)) and last_mod:
                last_modified[maintainer].append(last_mod)
    out = []
    for maintainer, members in sorted(by_maintainer.items()):
        if len(members) < min_members:
            continue
        member_repos = repos[maintainer]
        if all(member_repos):
            common = set.intersection(*member_repos)
            if common:
                # Every member sources from the same repo: H052's family, not
                # a coordinated adoption.
                continue
        if _one_related_cluster(members):
            # Every member is a naming variant of one project (the
            # appattic/appattic-bin/appattic-qt release shape): H052's
            # family by name, not a coordinated adoption.
            continue
        dormant_count = sum(
            1 for lm in last_modified[maintainer] if lm < dormant_cutoff)
        first_seen_ts = _maintainer_first_seen_ts(maintainer)
        novel = first_seen_ts is not None and first_seen_ts >= novel_cutoff
        escalated = novel and dormant_count >= min_dormant
        which = sorted(predicates[maintainer])
        all_repos = sorted({r for rs in member_repos for r in rs})
        match = (f"maintainer adopted {len(members)} unrelated packages "
                 "in the window")
        if escalated:
            match += (f" (first-seen account, {dormant_count} dormant "
                      "targets)")
        out.append({
            "rule_id": "G003",
            "name": "Coordinated Adoption",
            "severity": "HIGH" if escalated else "MEDIUM",
            "category": "correlation",
            "match": match,
            "params": {"members": sorted(members), "predicates": which,
                       "repos": all_repos, "novel": novel,
                       "dormant_count": dormant_count},
        })
    return out


def shared_upstream_dependency(records, min_packages: int = 2) -> list[dict]:
    """G004: the same upstream dependency added across packages in the window.

    A name and its host added to committed manifests (the U-series change
    view) in at least *min_packages* distinct packages: the same-new-
    upstream-dependency campaign shape, one alert naming the members.
    """
    by_dep: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in records:
        for entry in record.get("upstream_dep_additions", ()) or ():
            if isinstance(entry, (list, tuple)):
                name = str(entry[0]) if entry else ""
                host = str(entry[1]) if len(entry) > 1 else ""
            else:
                name, host = str(entry), ""
            if name:
                by_dep[(name, host)].add(str(record.get("package", "")))
    out = []
    for (name, host), members in sorted(by_dep.items()):
        if len(members) >= min_packages:
            where = f" from {host}" if host else ""
            out.append({
                "rule_id": "G004",
                "name": "Shared Upstream Dependency",
                "severity": "HIGH", "category": "correlation",
                "match": (f"upstream dependency {name}{where} appears in "
                          f"{len(members)} packages in the window"),
                "params": {"members": sorted(members), "dependency": name,
                           "host": host},
            })
    return out


def impersonation_campaign(records, min_members: int = 3) -> list[dict]:
    """G005: many name-clones of popular packages under one maintainer.

    Each record carries ``impersonated_target`` when its package name
    resembles a *far* more popular AUR package (the corpus H029 check over
    AUR vote counts).  A single maintainer publishing several such clones in
    one window is the registry-impersonation campaign that the per-package
    H029 only whispers about - 242 near-identical typosquats read as one
    campaign, not 242 findings.  This is the alert that names the campaign,
    its maintainer and its targets.

    Grouping is by maintainer key only.  Packages with **no** maintainer are
    not pooled into a synthetic "one submitter": an empty maintainer field is
    not evidence that unrelated ownerless packages share an operator.  Those
    clones stay individual H029 findings until something independently links
    them.
    """
    by_maintainer: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for record in records:
        target = str(record.get("impersonated_target", "") or "")
        if not target:
            continue
        member = str(record.get("package", ""))
        maintainer = str(record.get("maintainer", "") or "")
        if maintainer:
            by_maintainer[maintainer].append((member, target))
    out: list[dict] = []
    for maintainer, pairs in sorted(by_maintainer.items()):
        members = sorted({member for member, _ in pairs})
        if len(members) < min_members:
            continue
        targets = sorted({target for _, target in pairs})
        out.append({
            "rule_id": "G005",
            "name": "Impersonation Campaign",
            "severity": "HIGH", "category": "correlation",
            "match": (f"maintainer {maintainer} published {len(members)} "
                      f"name-clones of popular packages "
                      f"({', '.join(targets[:5])})"),
            "params": {"members": members, "maintainer": maintainer,
                       "targets": targets, "count": len(members)},
        })
    return out


def first_seen_adoption_burst(records, config=None) -> list[dict]:
    """G008: a first-seen account adopting many dormant packages at once.

    An account is *first-seen* when its earliest maintainer-event in the
    local property timeline falls within the current cycle window -- it has
    no prior maintainer history in the database.  Registration date is not
    in the RPC metadata and chasing profile pages would be a new fetch, so
    first-seen is the deterministic, self-contained approximation.  A
    throwaway account has, by definition, no prior maintainer events.

    The dormant-target clause is the false-positive killer: a legitimate new
    maintainer adopts a package or two they care about; nobody's first act is
    sweeping up orphans.  The conjunction of first-seen, many targets, and
    dormant targets is near-zero FP.  All parameters are config-driven and
    fingerprint-covered.
    """
    from ..db import maintainer_first_seen
    from ..db._history import _parse_ts

    thresholds = _thresholds(config)
    min_packages = int(thresholds.get("g008", {}).get("min_packages", 5))
    window_days = int(thresholds.get("g008", {}).get("window_days", 7))
    min_dormant = int(thresholds.get("g008", {}).get("min_dormant", 3))
    dormant_days = int(thresholds.get("g008", {}).get("dormant_days", 180))

    now = time.time()
    window_start = now - window_days * 86400
    dormant_cutoff = now - dormant_days * 86400

    by_maintainer: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        if not record.get("adoption"):
            continue
        maintainer = str(record.get("maintainer", "") or "").strip()
        if maintainer:
            by_maintainer[maintainer].append(record)

    out: list[dict] = []
    for maintainer, events in sorted(by_maintainer.items()):
        first_seen = maintainer_first_seen(maintainer)
        if first_seen is None:
            continue
        try:
            first_seen_ts = _parse_ts(first_seen).timestamp()
        except (ValueError, TypeError):
            continue
        if first_seen_ts < window_start:
            continue

        packages_in_window: list[str] = []
        dormant_count = 0
        for event in events:
            observed_at = event.get("adoption_observed_at", "")
            if not observed_at:
                continue
            try:
                observed_ts = _parse_ts(observed_at).timestamp()
            except (ValueError, TypeError):
                continue
            if observed_ts < window_start:
                continue
            pkg = str(event.get("package", ""))
            if pkg and pkg not in packages_in_window:
                packages_in_window.append(pkg)
            last_mod = event.get("last_modified", 0)
            if last_mod and isinstance(last_mod, (int, float)):
                if last_mod < dormant_cutoff:
                    dormant_count += 1

        if len(packages_in_window) >= min_packages and dormant_count >= min_dormant:
            out.append({
                "rule_id": "G008",
                "name": "First-Seen Account Adoption Burst",
                "severity": "HIGH", "category": "correlation",
                "match": (f"first-seen account {maintainer} adopted "
                          f"{len(packages_in_window)} packages "
                          f"({dormant_count} dormant) within {window_days} days"),
                "params": {
                    "maintainer": maintainer,
                    "members": sorted(packages_in_window),
                    "dormant_count": dormant_count,
                    "window_days": window_days,
                },
            })
    return out


def watchlisted_maintainer(records, config=None) -> list[dict]:
    """G009: a package or maintainer on the operator watchlist.

    Report-only (INFO, weight 0).  A package entry is the operator asking for
    that package to be named; a maintainer entry carries a human's judgement
    about an account, where registration date, "Inactive since" and suspension
    state are profile-page facts the pipeline never fetches.

    Maintainer entries are matched by salted hash, never a plaintext identity.
    Package entries are stored as written because package names are already
    public.  The watchlist is absent on a clean install, so this is silent
    until an operator curates one.
    """
    g009 = _thresholds(config).get("g009", {})
    if not g009.get("enabled", True):
        return []
    from ..watchlist import load_packages, load_watchlist, local_hash

    path = g009.get("path") or None
    entries = load_watchlist(path)
    packages = load_packages(path)
    if not entries and not packages:
        return []

    out: list[dict] = []
    seen: set[str] = set()
    for record in records:
        package = str(record.get("package", ""))
        if package in seen:
            continue
        if package in packages:
            label = packages[package]
            subject = "package"
        else:
            maintainer = str(record.get("maintainer", "") or "").strip()
            if not maintainer:
                continue
            name_hash = local_hash(maintainer)
            if not name_hash or name_hash not in entries:
                continue
            label = entries[name_hash]
            subject = "maintainer"
        seen.add(package)
        out.append({
            "rule_id": "G009",
            "name": "Watchlisted Subject",
            "severity": "INFO", "category": "correlation",
            "match": (f"{subject} is on the operator watchlist"
                      + (f" ({label})" if label else "")),
            "params": {"members": [package], "label": label,
                       "subject": subject},
        })
    return out


def correlate(records, config=None) -> list[dict]:
    """All G-series findings for one cycle's records."""
    thresholds = _thresholds(config)
    host_n = int(thresholds.get("g_host", {}).get("min_packages", 5))
    blob_n = int(thresholds.get("g_blob", {}).get("min_packages", 2))
    blob_len = int(thresholds.get("g_blob", {}).get("min_length", 256))
    adopt_m = int(thresholds.get("g_adopt", {}).get("min_members", 3))
    dep_n = int(thresholds.get("g_dep", {}).get("min_packages", 2))
    imp_m = int(thresholds.get("g_impersonation", {}).get("min_members", 3))
    out: list[dict] = []
    out.extend(shared_gained_host(records, host_n))
    out.extend(shared_added_literal(records, blob_n, blob_len))
    out.extend(coordinated_adoption(records, adopt_m, config))
    out.extend(shared_upstream_dependency(records, dep_n))
    out.extend(impersonation_campaign(records, imp_m))
    out.extend(watchlisted_maintainer(records, config))
    return out
