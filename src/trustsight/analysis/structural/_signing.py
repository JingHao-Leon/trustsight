"""Extracted from structural.py: _signing."""

import re
from ...rules import find_line_in_diff
from ...diffdoc import parse_diff_lines
from ...tokenizer import split_lines

__all__ = ['_LFS_OID_RE', '_SUBMODULE_COMMIT_RE', '_VALIDPGPKEYS_ENTRY_RE', '_VALIDPGPKEYS_LINE_RE', '_signing_key_findings', '_unread_carrier_findings']

_VALIDPGPKEYS_ENTRY_RE = re.compile(r"[\'\"]([A-Fa-f0-9]{8,40})[\'\"]")

_VALIDPGPKEYS_LINE_RE = re.compile(r"^\s*validpgpkeys\s*=|^\s*validpgpkeys\s*=?\s*\(", re.IGNORECASE)

def _signing_key_findings(diff_text: str, add) -> None:
    """The set of keys trusted to sign this package's sources changed (H078).

    ``validpgpkeys`` is the list of key fingerprints whose signature makepkg
    will accept for a signed source.  Whoever holds one of those keys can
    ship code to every user of the package, so the set changing is a trust
    change, and the diff states it as a declared fact.

    H024 owns the *removal* case (verification taken away).  H078 owns the
    other two:

    - a key **replaced** (one fingerprint out, a different one in) means the
      same sources are now trusted under a different holder: HIGH.
    - a key **added** to an existing set widens who may sign: MEDIUM.

    Introducing ``validpgpkeys`` where there was none is signature checking
    being switched on, so it is reported as a neutral fact at INFO rather
    than as a finding against the package.
    """
    added_keys: set[str] = set()
    removed_keys: set[str] = set()
    had_keys_before = False
    in_added = in_removed = False
    # The dominant AUR edit shape opens the array on a CONTEXT line and
    # changes one quoted key per `+`/`-` line:
    #     validpgpkeys=(
    #    -        'OLDKEY...')
    #   +        'NEWKEY...')
    # `array_open` carries that opener, or the `+`/`-` member lines are
    # never collected (the context branch used to reset the state instead).
    # It ends on a context line holding `)` or at a file/hunk header - not
    # on a member line's `)`, because the removal side closes before the
    # addition side has been read.  Collection is gated by the quoted-hex
    # entry regex, so a trailing unclosed region gathers nothing real.
    array_open = False
    for line in parse_diff_lines(split_lines(diff_text)).lines:
        raw = line.raw
        if raw.startswith(("+++ ", "--- ", "@@")):
            array_open = in_added = in_removed = False
            continue
        if line.is_content:
            side = {"add": "+", "remove": "-", "context": " "}[line.side]
            body = line.content
        else:
            side = " "
            body = raw
        opens = bool(_VALIDPGPKEYS_LINE_RE.match(body))
        if side == "-" and (opens or in_removed or array_open):
            had_keys_before = had_keys_before or bool(_VALIDPGPKEYS_ENTRY_RE.search(body))
            removed_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_removed = ")" not in body
            continue
        if side == "+" and (opens or in_added or array_open):
            added_keys |= {m.upper() for m in _VALIDPGPKEYS_ENTRY_RE.findall(body)}
            in_added = ")" not in body
            continue
        if side == " ":
            if opens:
                array_open = ")" not in body
            elif array_open:
                if _VALIDPGPKEYS_ENTRY_RE.search(body):
                    had_keys_before = True
                if ")" in body:
                    array_open = False
            in_added = in_removed = False

    genuinely_added = added_keys - removed_keys
    genuinely_removed = removed_keys - added_keys
    if not genuinely_added:
        return
    keys = ", ".join(sorted(k[-8:] for k in genuinely_added))
    line_no = find_line_in_diff(diff_text, r"validpgpkeys")
    if genuinely_removed:
        add("H078", "Signing Key Replaced", "HIGH", "integrity",
            f"validpgpkeys now trusts {keys} instead of "
            f"{', '.join(sorted(k[-8:] for k in genuinely_removed))}",
            line=line_no, added_keys=keys,
            removed_keys=", ".join(sorted(k[-8:] for k in genuinely_removed)),
            detail=f"signing key replaced: now {keys}")
    elif had_keys_before:
        add("H078", "Signing Key Added", "MEDIUM", "integrity",
            f"validpgpkeys gained {keys}; another holder may now sign this "
            f"package's sources",
            line=line_no, added_keys=keys,
            detail=f"signing key {keys} added to an existing set")
    else:
        add("H078", "Signature Verification Introduced", "INFO", "integrity",
            f"validpgpkeys introduced with {keys}",
            line=line_no, added_keys=keys,
            detail=f"validpgpkeys introduced with {keys}")

_SUBMODULE_COMMIT_RE = re.compile(r"^([+-])Subproject commit ([0-9a-f]{7,40})", re.M)

_LFS_OID_RE = re.compile(r"^([+-])\s*oid\s+sha256:([0-9a-f]{16,64})", re.M)

def _unread_carrier_findings(diff_text, pkgver_changed, add) -> None:
    """Contents this analysis cannot read, whose identity changed (C008).

    The upstream-payload gap is real and documented: a checksummed tarball's
    bytes are not in the diff, so the recipe can look untouched while the
    code it builds is replaced.  What *is* in the diff is the carrier's
    identity - the checksum, the commit, the OID - and a change to that with
    no version change is the same event H033 already claims for a git ref
    and C001 for a checksum.

    Two carriers had no such claim.  A submodule gitlink names code the
    repository does not contain; an LFS pointer names bytes that are not
    there either.  Moving one is a content change with no content in the
    diff, which is precisely the shape that reads as "nothing happened".

    The version distinguishes the two readings, as it does for H033: an
    upstream bump moves the pointer *and* the version, and moving it while
    the version stands still means anyone who already built this version
    gets different code than anyone who builds it now.
    """
    for label, pattern, what in (
        ("submodule", _SUBMODULE_COMMIT_RE, "a submodule commit"),
        ("lfs", _LFS_OID_RE, "a Git-LFS object id"),
    ):
        before = {m.group(2) for m in pattern.finditer(diff_text)
                  if m.group(1) == "-"}
        after = {m.group(2) for m in pattern.finditer(diff_text)
                 if m.group(1) == "+"}
        moved = sorted(after - before)
        if not (before and moved):
            continue
        old = sorted(before)[0][:12]
        new = moved[0][:12]
        if pkgver_changed:
            add("C009", "Unread Content Moved With The Version", "INFO",
                "integrity",
                f"{what} moved from {old} to {new} alongside a version bump",
                line=find_line_in_diff(diff_text, moved[0][:12]),
                carrier=label, old_id=old, new_id=new)
        else:
            add("C008", "Unread Content Moved Under A Stable Version", "HIGH",
                "integrity",
                f"{what} moved from {old} to {new} while pkgver did not change; "
                f"the bytes it names are not in this diff",
                line=find_line_in_diff(diff_text, moved[0][:12]),
                carrier=label, old_id=old, new_id=new)
        return
