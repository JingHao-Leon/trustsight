#!/usr/bin/env python3
"""Verify a baseline release directory against the channel contract.

A baseline release is the whole family: seed, runtime corpus and manifest,
each with a detached Ed25519 signature under the pinned distribution key.
The calibration corpus is the one unsigned CI-only sibling.  This check is
used offline by the test suite and in the release workflow after the family
is assembled, before anything is uploaded.

Usage:
    python scripts/verify_baseline_release.py --dir dist
    python scripts/verify_baseline_release.py --dir /tmp/assets --pubkey key.raw
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINNED = ROOT / "src" / "trustsight" / "full_aur" / "baseline_pubkey.pem"
REQUIRED = ("baseline-seed.tar.gz", "baseline-corpus.tar.zst",
            "baseline-manifest.json")
CI_ONLY = "baseline-benign-corpus.tar.gz"


def _verify(pubkey: bytes, data: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, data)
        return True
    except Exception:
        return False


def verify(directory: Path, pubkey: bytes) -> list[str]:
    problems: list[str] = []
    for name in REQUIRED:
        if not (directory / name).exists():
            problems.append(f"missing asset: {name}")
        if not (directory / f"{name}.sig").exists():
            problems.append(f"missing signature: {name}.sig")
    if problems:
        return problems

    for name in REQUIRED:
        data = (directory / name).read_bytes()
        sig = (directory / f"{name}.sig").read_bytes()
        if not _verify(pubkey, data, sig):
            problems.append(f"signature does not verify against the pinned key: {name}")

    manifest = json.loads((directory / "baseline-manifest.json").read_text())
    recorded = str(manifest.get("distribution_pubkey") or "").lower()
    if recorded and recorded != pubkey.hex():
        problems.append("manifest distribution_pubkey does not match the pinned key")
    assets = {row["name"]: row for row in manifest.get("assets") or []}
    for name in ("baseline-seed.tar.gz", "baseline-corpus.tar.zst"):
        row = assets.get(name)
        if row is None:
            problems.append(f"manifest does not list {name}")
            continue
        data = (directory / name).read_bytes()
        if row.get("sha256") != hashlib.sha256(data).hexdigest():
            problems.append(f"manifest sha256 mismatch: {name}")
        if row.get("size") != len(data):
            problems.append(f"manifest size mismatch: {name}")
        if row.get("signature") != (directory / f"{name}.sig").read_bytes().hex():
            problems.append(f"manifest signature does not match {name}.sig")

    if CI_ONLY in assets:
        problems.append(f"{CI_ONLY} must not be in the signed manifest")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--pubkey", type=Path, default=PINNED,
                        help="raw 32-byte distribution public key")
    args = parser.parse_args()

    if not args.dir.is_dir():
        print(f"not a directory: {args.dir}", file=sys.stderr)
        return 2
    pubkey = args.pubkey.read_bytes()
    if len(pubkey) != 32:
        print(f"{args.pubkey}: expected 32 raw bytes, got {len(pubkey)}",
              file=sys.stderr)
        return 2
    problems = verify(args.dir, pubkey)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"baseline family verified: {', '.join(REQUIRED)} (+ detached signatures)")
    if (args.dir / CI_ONLY).exists():
        print(f"unsigned CI-only sibling present: {CI_ONLY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
