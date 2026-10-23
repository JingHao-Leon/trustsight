"""The baseline channel contract is executable, not prose."""

import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def _family(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    raw = tmp_path / "key.raw"
    raw.write_bytes(key.private_bytes_raw())
    pub = tmp_path / "pub.raw"
    pub.write_bytes(key.public_key().public_bytes_raw())
    seed = tmp_path / "seed.tar.gz"
    seed.write_bytes(b"seed-bytes")
    corpus = tmp_path / "corpus.tar.zst"
    corpus.write_bytes(b"corpus-bytes")
    out = tmp_path / "dist"
    subprocess.run([
        sys.executable, str(ROOT / "scripts" / "build_release_baselines.py"),
        "--out", str(out), "--sign-key", str(raw),
        "--seed-archive", str(seed), "--corpus", str(corpus),
    ], check=True, capture_output=True, text=True)
    return out, pub


def test_the_signed_family_verifies(tmp_path):
    out, pub = _family(tmp_path)
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "verify_baseline_release.py"),
        "--dir", str(out), "--pubkey", str(pub),
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_a_missing_signature_fails(tmp_path):
    out, pub = _family(tmp_path)
    (out / "baseline-seed.tar.gz.sig").unlink()
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts" / "verify_baseline_release.py"),
        "--dir", str(out), "--pubkey", str(pub),
    ], capture_output=True, text=True)
    assert result.returncode == 1
    assert "missing signature" in result.stderr
