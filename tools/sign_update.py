#!/usr/bin/env python3
"""Sign a Reap3r agent binary and emit manifest.json with Ed25519 signature."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import os
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception as exc:  # pragma: no cover
    print("Missing dependency: cryptography", file=sys.stderr)
    print("Install with: pip install cryptography", file=sys.stderr)
    print(f"Import error: {exc}", file=sys.stderr)
    raise SystemExit(2)


def load_private_key_hex(args: argparse.Namespace) -> str:
    env_key = os.getenv("REAP3R_UPDATE_PRIVKEY_HEX", "").strip()
    if env_key:
        return env_key

    if args.private_key_hex:
        return args.private_key_hex.strip()

    if args.private_key_file:
        return Path(args.private_key_file).read_text(encoding="utf-8").strip()

    raise ValueError(
        "Missing private key. Set REAP3R_UPDATE_PRIVKEY_HEX, "
        "or pass --private-key-hex / --private-key-file.",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign update binary and generate signed manifest.",
    )
    parser.add_argument("--binary", required=True, help="Path to agent binary.")
    parser.add_argument("--version", required=True, help="Version string to publish.")
    parser.add_argument("--download-url", required=True, help="Public HTTPS URL used by agents.")
    parser.add_argument("--os", default="windows", help="Target OS label (default: windows).")
    parser.add_argument("--arch", default="x86_64", help="Target arch label (default: x86_64).")
    parser.add_argument("--private-key-hex", default="", help="Ed25519 private key hex (32 bytes).")
    parser.add_argument("--private-key-file", default="", help="Path to file containing private key hex.")
    parser.add_argument("--signer-thumbprint", default="", help="Optional Windows Authenticode signer thumbprint.")
    parser.add_argument(
        "--require-authenticode",
        action="store_true",
        help="Mark manifest to require Authenticode verification on agent side.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output manifest path. Default: <binary>.manifest.json",
    )
    args = parser.parse_args()

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists() or not binary_path.is_file():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    private_hex = load_private_key_hex(args)
    private_raw = bytes.fromhex(private_hex)
    if len(private_raw) != 32:
        raise ValueError("Invalid Ed25519 private key length. Expected 32 bytes hex.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    binary_bytes = binary_path.read_bytes()
    sha256 = hashlib.sha256(binary_bytes).hexdigest()
    signature = private_key.sign(binary_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    manifest = {
        "version": args.version,
        "os": args.os,
        "arch": args.arch,
        "sha256": sha256,
        "size": len(binary_bytes),
        "download_url": args.download_url,
        "sig_ed25519": signature_b64,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    if args.signer_thumbprint:
        manifest["signer_thumbprint"] = args.signer_thumbprint.strip().upper()
    if args.require_authenticode:
        manifest["require_authenticode"] = True

    out_path = Path(args.out).resolve() if args.out else Path(str(binary_path) + ".manifest.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Signed manifest: {out_path}")
    print(f"sha256: {sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
