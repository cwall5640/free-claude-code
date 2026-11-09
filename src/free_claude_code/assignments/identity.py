# SPDX-License-Identifier: AGPL-3.0-only
"""Per-install worker identity. claude1 is only the default example.

A second laptop uses another file. The worker modules that verify manager
keys do not read the verdict private key; they pass its path to the signer.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden

_BARE = re.compile(r"claude[1-9][0-9]*\Z")


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    actor_name: str
    bare_name: str
    branch_prefix: str
    comment_signature: str
    waiting_label: str
    github_login: str
    verdict_key_file: Path | None = None
    slack_channel_id: str = ""
    slack_enabled: bool = False
    fcc_launcher: str = ""

    def comment_suffix(self) -> str:
        return f"\n{self.comment_signature}\n"

    def feature_branch(self, task_id: str) -> str:
        lowered = task_id.strip().lower()
        return f"{self.branch_prefix}/{lowered}"

    def own_logins(self) -> frozenset[str]:
        return frozenset({self.actor_name, self.bare_name, self.github_login})


def default_worker_identity() -> WorkerIdentity:
    """Example install. Replace the file to run claude2 or another worker."""

    return WorkerIdentity(
        actor_name="dev:claude1",
        bare_name="claude1",
        branch_prefix="claude1",
        comment_signature="— dev:claude1",
        waiting_label="waiting:claude1",
        github_login="claude1",
    )


def load_worker_identity(path: Path) -> WorkerIdentity:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise Forbidden("worker identity config must be an object")
    key_text = str(raw.get("verdict_key_file", "")).strip()
    key_path = None
    if key_text:
        candidate = Path(key_text)
        key_path = candidate if candidate.is_absolute() else path.parent / candidate
    identity = WorkerIdentity(
        actor_name=str(raw.get("actor_name", "")).strip(),
        bare_name=str(raw.get("bare_name", "")).strip(),
        branch_prefix=str(raw.get("branch_prefix", "")).strip().strip("/"),
        comment_signature=str(raw.get("comment_signature", "")).strip(),
        waiting_label=str(raw.get("waiting_label", "")).strip(),
        github_login=str(raw.get("github_login", "")).strip(),
        verdict_key_file=key_path,
        slack_channel_id=str(raw.get("slack_channel_id", "")).strip(),
        slack_enabled=_slack_enabled(raw),
        fcc_launcher=str(raw.get("fcc_launcher", "")).strip(),
    )
    validate_worker_identity(identity)
    return identity


def validate_worker_identity(identity: WorkerIdentity) -> None:
    if not _BARE.fullmatch(identity.bare_name):
        raise Forbidden("worker bare name must be claudeN")
    if identity.actor_name != f"dev:{identity.bare_name}":
        raise Forbidden("actor name must be dev: plus the bare name")
    if identity.branch_prefix != identity.bare_name:
        raise Forbidden("branch prefix must be the bare name")
    if identity.waiting_label != f"waiting:{identity.bare_name}":
        raise Forbidden("waiting label must match the bare name")
    if identity.comment_signature != f"— {identity.actor_name}":
        raise Forbidden("comment signature must name this actor")
    if not identity.github_login:
        raise Forbidden("worker github login is required")
    if identity.slack_channel_id and not re.fullmatch(r"C[A-Z0-9]{8,}", identity.slack_channel_id):
        raise Forbidden("slack channel id must be one channel")
    if identity.slack_enabled and not identity.slack_channel_id:
        raise Forbidden("slack handoff needs the configured channel id")
    if identity.fcc_launcher and not _launcher_is_absolute(identity.fcc_launcher):
        raise Forbidden("fcc launcher must be an absolute path")
    if "\n" in identity.fcc_launcher or "\r" in identity.fcc_launcher:
        raise Forbidden("fcc launcher path is invalid")


def _launcher_is_absolute(text: str) -> bool:
    if text.startswith("/") or text.startswith("\\"):
        return True
    return len(text) >= 3 and text[1] == ":" and text[2] in "\\/"


def _slack_enabled(raw: dict[str, object]) -> bool:
    flag = raw.get("slack_enabled", False)
    if not isinstance(flag, bool):
        raise Forbidden("slack_enabled must be a boolean")
    return flag
