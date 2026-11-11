# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable records for one allowlisted GitHub assignment."""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from free_claude_code.assignments.errors import Forbidden, ScopeError
from free_claude_code.assignments.paths import safe_relative

# Import commit this adapter was written against. Not a model invocation.
SOURCE_PIN = "61e5d7d50acd61345a25e77c66dd3acc795b3716"
# Same id as DEFAULT_MODEL in this pin. The adapter never calls it.
INTENDED_MODEL = "nvidia_nim/nvidia/nemotron-3-ultra-550b-a55b"
EXECUTION_MODE = "gated_sandbox"
SCHEMA = "fcc-assignment-manifest/v1"
# The one name for the task card: the launcher plants the issue text under
# this name in the model workspace, the prompt references exactly this name,
# and the handoff artifact uses it too. One constant, no drift (FCC #26).
TASK_CARD_NAME = "untrusted-issue.md"

Phase = Literal["execute", "publish", "ci_rerun", "workflow_edit"]
_FORBIDDEN_BRANCHES = frozenset({"main", "master"})


def _canonical(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """One issue a local operator may fetch. Not derived from issue text."""

    owner: str
    repo: str
    issue_number: int
    base_branch: str


@dataclass(frozen=True, slots=True)
class AssignmentConfig:
    """Default-off local policy. Nothing here is read from GitHub."""

    enabled: bool = False
    allowlist: tuple[AllowlistEntry, ...] = ()
    operators: tuple[str, ...] = ()
    forbidden_branches: tuple[str, ...] = ("main", "master")
    allowed_path_prefixes: tuple[str, ...] = ()
    setup_command: tuple[str, ...] = ()
    max_patch_bytes: int = 200_000
    fetch_timeout_seconds: float = 10.0


@dataclass(frozen=True, slots=True)
class IssueSnapshot:
    owner: str
    repo: str
    number: int
    title: str
    body: str
    state: str
    updated_at: str
    node_id: str

    def revision(self) -> str:
        return digest(
            {
                "body": self.body,
                "node_id": self.node_id,
                "number": self.number,
                "owner": self.owner,
                "repo": self.repo,
                "state": self.state,
                "title": self.title,
                "updated_at": self.updated_at,
            }
        )


@dataclass(frozen=True, slots=True)
class Scope:
    allowed_prefixes: tuple[str, ...]
    max_patch_bytes: int
    setup_command: tuple[str, ...] = ()

    def fingerprint(self) -> str:
        return digest(
            {
                "allowed_prefixes": self.allowed_prefixes,
                "max_patch_bytes": self.max_patch_bytes,
                "setup_command": list(self.setup_command),
            }
        )


@dataclass(frozen=True, slots=True)
class ModelProvenance:
    """Records the intended NVIDIA model without calling it."""

    provider: str = "nvidia_nim"
    model: str = INTENDED_MODEL
    invoked: bool = False
    source_pin: str = SOURCE_PIN

    def __post_init__(self) -> None:
        if self.invoked:
            raise Forbidden("this adapter cannot record a model invocation")


@dataclass(frozen=True, slots=True)
class TaskManifest:
    """Fetched assignment. Issue text is data, never shell authority."""

    task_key: str
    owner: str
    repo: str
    issue_number: int
    issue_revision: str
    title_redacted: str
    base_branch: str
    base_sha: str
    scope: Scope
    shell_authority: bool = False
    execution_mode: str = EXECUTION_MODE
    bypass_native_approvals: bool = False
    model: ModelProvenance = ModelProvenance()
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.shell_authority is not False:
            raise Forbidden("issue text cannot be granted shell authority")
        if self.execution_mode != EXECUTION_MODE:
            raise Forbidden("repository execution is not available")
        if self.bypass_native_approvals:
            raise Forbidden("native machine approvals cannot be bypassed")

    @property
    def manifest_id(self) -> str:
        return digest(
            {
                "base_branch": self.base_branch,
                "base_sha": self.base_sha,
                "execution_mode": self.execution_mode,
                "issue_number": self.issue_number,
                "issue_revision": self.issue_revision,
                "owner": self.owner,
                "repo": self.repo,
                "schema": self.schema,
                "scope": self.scope.fingerprint(),
                "shell_authority": False,
                "source_pin": self.model.source_pin,
                "task_key": self.task_key,
            }
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """Local operator decision for one phase. Comments cannot create this."""

    manifest_id: str
    phase: Phase
    operator_id: str
    issue_revision: str
    base_sha: str
    scope_fingerprint: str

    def __post_init__(self) -> None:
        if self.phase not in {"execute", "publish", "ci_rerun", "workflow_edit"}:
            raise Forbidden("unknown approval phase")
        if not self.operator_id.strip():
            raise Forbidden("operator id is required")


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    """Local pull-request description. Sending it is a separate approval."""

    manifest_id: str
    base_branch: str
    head_branch: str
    title: str
    body: str
    patch_sha256: str | None
    reviewer_id: str = ""
    author_id: str = ""
    auto_merge: bool = False
    direct_push: bool = False

    def __post_init__(self) -> None:
        if self.auto_merge or self.direct_push:
            raise Forbidden("auto-merge and direct push are not available")
        if self.head_branch in _FORBIDDEN_BRANCHES:
            raise Forbidden("refusing a protected head branch")
        if self.reviewer_id and self.reviewer_id == self.author_id:
            raise Forbidden("reviewer must be distinct from the author")


def validate_prefixes(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    checked: list[str] = []
    for prefix in prefixes:
        safe = safe_relative(prefix)
        if safe.startswith(".github/workflows"):
            raise ScopeError("workflow paths cannot be allowlisted")
        checked.append(safe)
    return tuple(checked)
