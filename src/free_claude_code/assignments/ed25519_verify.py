# SPDX-License-Identifier: AGPL-3.0-only
"""Verify Ed25519 signatures. This module cannot mint them."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_ed25519(public_key: bytes, payload: bytes, signature: bytes) -> bool:
    """Return whether `signature` is valid for `payload` under `public_key`."""

    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature:
        return False
    return True
