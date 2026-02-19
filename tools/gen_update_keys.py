#!/usr/bin/env python3
"""Generate Ed25519 keypair for Reap3r agent update signing."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception as exc:  # pragma: no cover
    print("Missing dependency: cryptography", file=sys.stderr)
    print("Install with: pip install cryptography", file=sys.stderr)
    print(f"Import error: {exc}", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Ed25519 update signing keys for Reap3r.",
    )
    parser.add_argument(
        "--out-dir",
        default="tools/update-keys",
        help="Directory where keys are written (default: tools/update-keys).",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    private_path = out_dir / "reap3r_update_private_key.hex"
    public_path = out_dir / "reap3r_update_public_key.hex"

    private_path.write_text(private_raw + "\n", encoding="utf-8")
    public_path.write_text(public_raw + "\n", encoding="utf-8")

    print(f"Private key: {private_path}")
    print(f"Public key : {public_path}")
    print("")
    print("Set in CI/Vault (private key, never in backend runtime):")
    print("  REAP3R_UPDATE_PRIVKEY_HEX=<private_key_hex>")
    print("")
    print("Embed in agent build:")
    print("  REAP3R_UPDATE_PUBKEY_HEX=<public_key_hex>")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
