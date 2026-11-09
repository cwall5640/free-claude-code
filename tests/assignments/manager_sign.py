# SPDX-License-Identifier: AGPL-3.0-only
"""Test-only manager signer. The worker package does not import this."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from free_claude_code.assignments.workflow import ManagerAttestation, _canonical


def new_key() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return secret, public


def sign_attestation(secret: bytes, attestation: ManagerAttestation) -> ManagerAttestation:
    signature = Ed25519PrivateKey.from_private_bytes(secret).sign(_canonical(attestation.signed_body()))
    return ManagerAttestation(
        principal_id=attestation.principal_id,
        role=attestation.role,
        audience=attestation.audience,
        owner=attestation.owner,
        repo=attestation.repo,
        issue_number=attestation.issue_number,
        issue_node_id=attestation.issue_node_id,
        base_branch=attestation.base_branch,
        base_sha=attestation.base_sha,
        updated_at=attestation.updated_at,
        task_id=attestation.task_id,
        nonce=attestation.nonce,
        expires_at=attestation.expires_at,
        decision=attestation.decision,
        signature=signature.hex(),
    )
