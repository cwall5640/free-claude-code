# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a claude1 verdict. This module cannot sign one."""

import json
from collections.abc import Mapping

from free_claude_code.assignments.ed25519_verify import verify_ed25519

_VERDICTS = frozenset({"PASS", "READY", "HOLD", "STALE"})


def verdict_payload(fields: Mapping[str, str]) -> bytes:
    """Canonical bytes a verdict public key signs. The em dash suffix is not included."""

    verdict = fields.get("verdict", "")
    head_sha = fields.get("head_sha", "")
    if verdict not in _VERDICTS or not head_sha:
        return b""
    body = {
        "actor": "dev:claude1",
        "findings": fields.get("findings", ""),
        "head_sha": head_sha,
        "limitations": fields.get("limitations", ""),
        "verdict": verdict,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_verdict(public_key: bytes, fields: Mapping[str, str], signature: bytes) -> bool:
    payload = verdict_payload(fields)
    if not payload:
        return False
    return verify_ed25519(public_key, payload, signature)
