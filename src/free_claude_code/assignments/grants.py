# SPDX-License-Identifier: AGPL-3.0-only
"""HMAC task grants. Issue text cannot sign or extend one."""

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import ApprovalInvalid, Forbidden
from free_claude_code.assignments.models import TaskManifest
from free_claude_code.assignments.private_io import append_private_bytes, ensure_private_dir


@dataclass(frozen=True, slots=True)
class ModelGrant:
    manifest_id: str
    repo: str
    base_sha: str
    issue_revision: str
    expires_at: int
    actions: tuple[str, ...]
    signature: str


def _payload(grant: ModelGrant) -> bytes:
    body = {
        "actions": list(grant.actions),
        "base_sha": grant.base_sha,
        "expires_at": grant.expires_at,
        "issue_revision": grant.issue_revision,
        "manifest_id": grant.manifest_id,
        "repo": grant.repo,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_grant(key: str, grant: ModelGrant) -> ModelGrant:
    signature = hmac.new(key.encode("utf-8"), _payload(grant), hashlib.sha256).hexdigest()
    return ModelGrant(
        manifest_id=grant.manifest_id,
        repo=grant.repo,
        base_sha=grant.base_sha,
        issue_revision=grant.issue_revision,
        expires_at=grant.expires_at,
        actions=grant.actions,
        signature=signature,
    )


def verify_grant(
    key: str,
    grant: ModelGrant,
    manifest: TaskManifest,
    *,
    now: int,
    action: str,
    revocations: set[str],
) -> None:
    expected = hmac.new(key.encode("utf-8"), _payload(grant), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, grant.signature):
        raise ApprovalInvalid("model grant signature is not valid")
    if grant.manifest_id in revocations:
        raise ApprovalInvalid("model grant was revoked")
    if now > grant.expires_at:
        raise ApprovalInvalid("model grant expired")
    if grant.manifest_id != manifest.manifest_id:
        raise ApprovalInvalid("model grant is for a different task")
    if grant.repo != f"{manifest.owner}/{manifest.repo}":
        raise Forbidden("model grant repository does not match")
    if grant.base_sha != manifest.base_sha or grant.issue_revision != manifest.issue_revision:
        raise ApprovalInvalid("model grant does not match the approved revision")
    if action not in grant.actions:
        raise Forbidden("model grant does not allow this action")


def load_revocations(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def revoke_grant(path: Path, manifest_id: str) -> None:
    ensure_private_dir(path.parent)
    append_private_bytes(path, (manifest_id + "\n").encode("utf-8"))
