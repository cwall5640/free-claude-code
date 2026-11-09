# SPDX-License-Identifier: AGPL-3.0-only
"""Load the assigning-manager set. Names are data, not code.

Each entry is one identity and its pinned Ed25519 public key. Adding or
removing a manager is a change to this file. This module cannot sign.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.handoff import actor_label

_ROLES = frozenset({"vibe", "project_manager"})


@dataclass(frozen=True, slots=True)
class ManagerIdentity:
    principal_id: str
    role: str
    display_name: str
    public_key: bytes
    github_login: str
    interim_until: str = ""
    handoff_actor: str = ""


def load_manager_config(path: Path) -> tuple[ManagerIdentity, ...]:
    """Return the configured managers. An empty file authorizes nobody."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("managers") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        raise Forbidden("manager config must contain a managers list")
    found: list[ManagerIdentity] = []
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, dict):
            raise Forbidden("manager config entry is not an object")
        principal_id = str(item.get("principal_id", "")).strip()
        role = str(item.get("role", "")).strip()
        display_name = str(item.get("display_name", "")).strip()
        github_login = str(item.get("github_login", "")).strip()
        interim_until = str(item.get("interim_until", "")).strip()
        handoff_actor = str(item.get("handoff_actor", "")).strip()
        key_hex = str(item.get("public_key_hex", "")).strip()
        if handoff_actor:
            actor_label(handoff_actor)
        if not principal_id or not display_name or not github_login:
            raise Forbidden("manager config entry is incomplete")
        if principal_id in seen:
            raise Forbidden("manager config repeats a principal")
        if role not in _ROLES:
            raise Forbidden("manager role is not an assigning role")
        try:
            public_key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise Forbidden("manager public key is not hex") from exc
        if len(public_key) != 32:
            raise Forbidden("manager public key must be 32 bytes")
        seen.add(principal_id)
        found.append(
            ManagerIdentity(
                principal_id=principal_id,
                role=role,
                display_name=display_name,
                public_key=public_key,
                github_login=github_login,
                interim_until=interim_until,
                handoff_actor=handoff_actor,
            )
        )
    return tuple(found)
