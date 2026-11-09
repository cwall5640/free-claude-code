# SPDX-License-Identifier: AGPL-3.0-only
"""Automatic assignment candidate. Live startup and activation stay off.

A verified manager attestation can drive one claim, local repair budget,
feature-branch publication, and a return to that manager. A label, display
name, or shared login is not authority. This module does not merge, does not
create GitHub issues, does not install a sign-in task, and does not call a
model or the network by itself.
"""

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    Conflict,
    Disabled,
    Forbidden,
    MergeRejected,
)
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.paths import contained, safe_relative
from free_claude_code.assignments.redact import redact

ROUTING_LABEL = "dev:claude1"
REPAIR_LIMIT = 2
HOSTED_RUNNER_LABELS = frozenset(
    {"ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "windows-latest", "macos-latest"}
)
INKBOUND_RUNNER_LABELS = frozenset({"dell", "inkbound"})
SECURITY_OVERRIDES = frozenset(
    {"merge", "hosted_ci", "skip_permissions", "activate", "use_inkbound", "paid_ci"}
)
PUBLISHER_ENV = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "FCC_PUBLISH_TOKEN",
)

# Honest boundary. Tests may pass while every live operation below stays unproved.
CAPABILITY_BOUNDARY = {
    "state_machine": "implemented",
    "manager_origin": "hmac_principal_not_display_name",
    "label_dev_claude1": "routing_only",
    "live_github": "unproved",
    "issue_creation": "unsupported_http_403_no_alternate_principal",
    "model_inference": "not_invoked",
    "startup_installer": "disabled",
    "activation": "disabled",
    "merge": "refused",
    "hosted_or_paid_ci": "refused",
    "inkbound_runners": "not_repurposed",
    "windows_dacl": "unverified",
    "windows_reparse": "unverified",
    "native_powershell": "not_executed",
    "end_to_end": "not_claimed",
}


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _sign(key: str, payload: Mapping[str, object]) -> str:
    return hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class GitHubTaskRecord:
    """Fields read from a GitHub issue and its base ref. Body text is absent on purpose."""

    owner: str
    repo: str
    number: int
    node_id: str
    state: str
    updated_at: str
    base_branch: str
    base_sha: str
    labels: tuple[str, ...] = ()
    author_login: str = ""
    author_id: str = ""

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"


@dataclass(frozen=True, slots=True)
class ManagerAttestation:
    """Signed assignment from a manager principal. Display name is not a field."""

    principal_id: str
    role: str
    owner: str
    repo: str
    issue_number: int
    issue_node_id: str
    base_sha: str
    updated_at: str
    decision: str
    signature: str

    def signed_body(self) -> dict[str, object]:
        return {
            "base_sha": self.base_sha,
            "decision": self.decision,
            "issue_node_id": self.issue_node_id,
            "issue_number": self.issue_number,
            "owner": self.owner,
            "principal_id": self.principal_id,
            "repo": self.repo,
            "role": self.role,
            "updated_at": self.updated_at,
        }


def sign_attestation(key: str, attestation: ManagerAttestation) -> ManagerAttestation:
    signature = _sign(key, attestation.signed_body())
    return ManagerAttestation(
        principal_id=attestation.principal_id,
        role=attestation.role,
        owner=attestation.owner,
        repo=attestation.repo,
        issue_number=attestation.issue_number,
        issue_node_id=attestation.issue_node_id,
        base_sha=attestation.base_sha,
        updated_at=attestation.updated_at,
        decision=attestation.decision,
        signature=signature,
    )


@dataclass(frozen=True, slots=True)
class ProducerDecision:
    principal_id: str
    owner: str
    repo: str
    statement: str
    signature: str

    def signed_body(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "principal_id": self.principal_id,
            "repo": self.repo,
            "statement": self.statement,
        }


def sign_producer_decision(key: str, decision: ProducerDecision) -> ProducerDecision:
    return ProducerDecision(
        principal_id=decision.principal_id,
        owner=decision.owner,
        repo=decision.repo,
        statement=decision.statement,
        signature=_sign(key, decision.signed_body()),
    )


@dataclass(frozen=True, slots=True)
class WorkflowPolicy:
    worker_principal_id: str
    producer_principal_id: str
    producer_key: str
    manager_keys: Mapping[str, str]
    plan_blocked_repos: tuple[str, ...] = ()
    approved_runner_labels: tuple[str, ...] = ("self-hosted", "Windows", "X64")
    repair_limit: int = REPAIR_LIMIT


@dataclass(frozen=True, slots=True)
class MachineGate:
    signed_in: bool
    active: bool
    plugged_in: bool
    online: bool


@dataclass(frozen=True, slots=True)
class RepoAccess:
    pull: bool
    push: bool
    admin: bool = False
    maintain: bool = False


@dataclass(frozen=True, slots=True)
class StageResult:
    """A finished stage. Non-empty stderr is not an exit code."""

    stage: str
    exit_code: int
    stderr: str = ""
    kind: str = "test_failure"
    head_sha: str = ""


@dataclass(frozen=True, slots=True)
class StageRecord:
    stage: str
    exit_code: int
    detail: str
    passed: bool


@dataclass(frozen=True, slots=True)
class RunnerView:
    name: str
    repository: str
    labels: tuple[str, ...]
    online: bool
    busy: bool


@dataclass(frozen=True, slots=True)
class ManagerReturn:
    manager_principal_id: str
    status: str
    head_sha: str
    pr_url: str
    repair_attempts: int
    stages: tuple[StageRecord, ...]
    merged: bool = False


def record_stage(result: StageResult) -> StageRecord:
    """Keep the process exit code. Stderr is redacted and does not decide success."""

    return StageRecord(
        stage=result.stage,
        exit_code=result.exit_code,
        detail=redact(result.stderr),
        passed=result.exit_code == 0 and result.kind == "pass",
    )


def admit_machine(machine: MachineGate) -> str:
    if not machine.online:
        return "queue_offline"
    if not machine.signed_in:
        return "queue_signed_out"
    if not (machine.active and machine.plugged_in):
        return "queue_sleep"
    return "admit"


def start_from_label(_record: GitHubTaskRecord) -> None:
    raise Forbidden(f"label {ROUTING_LABEL} is not execution authority")


class StartupControls:
    """Sign-in startup is described here and refused until a later approval."""

    activation_enabled = False
    startup_installed = False

    def install(self) -> None:
        raise Disabled("startup installer is disabled pending separate approval")

    def activate(self) -> None:
        raise Disabled("activation is disabled pending separate approval")


class IssueCreation:
    """The earlier issue-create call returned 403. There is no second principal."""

    def __init__(self) -> None:
        self.attempts = 0

    def create_issue(self, *_args: object, **_kwargs: object) -> None:
        self.attempts += 1
        raise Forbidden(
            "GitHub issue creation is unsupported after HTTP 403; "
            "no alternate principal and no retry"
        )


class SeparatePublisher:
    """Opens a review pull request. It has no merge operation that succeeds."""

    def __init__(self, token: str) -> None:
        self._token = token
        self.opened: list[dict[str, str]] = []

    def __repr__(self) -> str:
        return "SeparatePublisher([redacted])"

    def open_pull_request(self, *, head: str, base: str, title: str, body: str) -> str:
        if base in {"main", "master"} or head in {"main", "master"}:
            raise MergeRejected("refusing a protected branch")
        self.opened.append({"base": base, "head": head, "title": title})
        return f"https://github.example/{head}"

    def merge(self, *_args: object, **_kwargs: object) -> None:
        raise MergeRejected("merge is not available to the worker")

    def model_environment(self, source: Mapping[str, str]) -> dict[str, str]:
        """Environment for a model or test child. Publication secrets are removed."""

        cleaned = scrub_env(dict(source))
        for name in PUBLISHER_ENV:
            cleaned.pop(name, None)
        return {key: value for key, value in cleaned.items() if value != self._token}


def runner_decision(runner: RunnerView, policy: WorkflowPolicy, record: GitHubTaskRecord) -> str:
    if runner.repository != f"{record.owner}/{record.repo}":
        return "wrong_repo"
    labels = {item.lower() for item in runner.labels}
    if labels & {item.lower() for item in HOSTED_RUNNER_LABELS}:
        return "hosted_refused"
    if labels & {item.lower() for item in INKBOUND_RUNNER_LABELS}:
        return "inkbound_refused"
    required = {item.lower() for item in policy.approved_runner_labels}
    if not required <= labels:
        return "labels_missing"
    if not runner.online or runner.busy:
        return "unavailable"
    return "eligible"


def refuse_reparse(path: Path) -> None:
    if path.is_symlink():
        raise Forbidden("refusing a symlink or reparse stand-in")


def assert_private_file(path: Path) -> None:
    """POSIX mode check. This is not a Windows DACL proof."""

    refuse_reparse(path)
    if path.stat().st_mode & 0o077:
        raise Forbidden("credential file is group or world accessible")


class ClaimLedger:
    """One active job. Completed and cancelled records are not revived."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._path = self.root / "claims.json"

    def _load(self) -> dict[str, object]:
        if not self._path.is_file():
            return {"active": "", "tasks": {}}
        loaded = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return {"active": "", "tasks": {}}
        return loaded

    def _save(self, payload: dict[str, object]) -> None:
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self._path)

    def get(self, key: str) -> dict[str, object] | None:
        tasks = self._load().get("tasks")
        if not isinstance(tasks, dict):
            return None
        found = tasks.get(key)
        return found if isinstance(found, dict) else None

    def claim(self, record: GitHubTaskRecord, worker_id: str) -> dict[str, object]:
        payload = self._load()
        tasks = payload.get("tasks")
        if not isinstance(tasks, dict):
            tasks = {}
        current = tasks.get(record.key)
        if isinstance(current, dict):
            if current.get("status") in {"completed", "cancelled", "stopped", "blocked"}:
                raise Conflict(f"assignment is {current.get('status')} and is not revived")
            if current.get("worker_id") not in {None, "", worker_id}:
                raise Conflict("another worker holds this assignment")
            if current.get("status") == "stale" or current.get("base_sha") != record.base_sha:
                current["status"] = "stale"
                tasks[record.key] = current
                payload["tasks"] = tasks
                payload["active"] = ""
                self._save(payload)
                raise ApprovalInvalid("base SHA changed under the claim")
            if current.get("status") == "active" and current.get("worker_id") == worker_id:
                return current
        active = str(payload.get("active") or "")
        if active and active != record.key:
            raise Conflict("one assignment is already active")
        claim = {
            "base_sha": record.base_sha,
            "repairs": int(current.get("repairs", 0)) if isinstance(current, dict) else 0,
            "status": "active",
            "worker_id": worker_id,
        }
        tasks[record.key] = claim
        payload["tasks"] = tasks
        payload["active"] = record.key
        self._save(payload)
        return claim

    def update(self, key: str, **fields: object) -> dict[str, object]:
        payload = self._load()
        tasks = payload.get("tasks")
        if not isinstance(tasks, dict) or not isinstance(tasks.get(key), dict):
            raise Conflict("claim is missing")
        claim = dict(tasks[key])
        claim.update(fields)
        tasks[key] = claim
        payload["tasks"] = tasks
        if claim.get("status") != "active":
            payload["active"] = ""
        self._save(payload)
        return claim


class AssignmentWorkflow:
    """Candidate state machine. Calling it does not enable startup or activation."""

    def __init__(self, policy: WorkflowPolicy, ledger: ClaimLedger) -> None:
        self.policy = policy
        self.ledger = ledger
        self.controls = StartupControls()
        self.issues = IssueCreation()

    def create_issue(self) -> None:
        self.issues.create_issue()

    def evaluate(
        self,
        record: GitHubTaskRecord,
        attestation: ManagerAttestation | None,
        *,
        machine: MachineGate,
        access: RepoAccess,
        stages: tuple[StageResult, ...],
        publisher: SeparatePublisher,
        runners: tuple[RunnerView, ...] = (),
        producer: ProducerDecision | None = None,
    ) -> ManagerReturn:
        self._verify_manager(record, attestation)
        assert attestation is not None
        if attestation.decision == "cancel":
            self._cancel(record)
            return self._return(attestation, "cancelled", "", "", 0, ())
        self._access(access)
        self._producer(record, producer)
        gate = admit_machine(machine)
        if gate != "admit":
            return self._return(attestation, gate, record.base_sha, "", 0, ())
        claim = self.ledger.claim(record, self.policy.worker_principal_id)
        logs: list[StageRecord] = []
        repairs = int(claim.get("repairs", 0))
        head = record.base_sha
        for result in stages:
            if result.stage == "ci":
                decision = self._ci_gate(record, runners)
                if decision != "eligible":
                    blocked = decision in {"hosted_refused", "inkbound_refused"}
                    logs.append(StageRecord("ci_refused" if blocked else "ci_unavailable", 2, decision, False))
                    status = "blocked" if blocked else "stopped"
                    self.ledger.update(record.key, status=status, repairs=repairs)
                    return self._return(attestation, status, head, "", repairs, tuple(logs))
            if result.kind in {"denial", "security"}:
                logged = record_stage(result)
                logs.append(logged)
                self.ledger.update(record.key, status="blocked", repairs=repairs)
                return self._return(attestation, "blocked", head, "", repairs, tuple(logs))
            logged = record_stage(result)
            logs.append(logged)
            if result.head_sha:
                head = result.head_sha
            if logged.passed:
                continue
            if repairs >= self.policy.repair_limit:
                self.ledger.update(record.key, status="stopped", repairs=repairs)
                return self._return(attestation, "stopped", head, "", repairs, tuple(logs))
            repairs += 1
            self.ledger.update(record.key, status="active", repairs=repairs)
        if not logs or not logs[-1].passed:
            self.ledger.update(record.key, status="stopped", repairs=repairs)
            return self._return(attestation, "stopped", head, "", repairs, tuple(logs))
        pr_url = publisher.open_pull_request(
            head=f"fcc-task/{record.number}-{record.base_sha[:12]}",
            base=record.base_branch,
            title=f"Review assignment #{record.number}",
            body=_evidence_body(record, attestation, head),
        )
        self.ledger.update(record.key, status="completed", repairs=repairs, head_sha=head)
        return self._return(attestation, "returned_for_review", head, pr_url, repairs, tuple(logs))

    def _cancel(self, record: GitHubTaskRecord) -> None:
        existing = self.ledger.get(record.key)
        if existing and existing.get("status") == "completed":
            raise Conflict("completed assignment is not cancelled into a new run")
        if existing is None:
            self.ledger.claim(record, self.policy.worker_principal_id)
        self.ledger.update(record.key, status="cancelled")

    def _verify_manager(
        self, record: GitHubTaskRecord, attestation: ManagerAttestation | None
    ) -> None:
        if attestation is None:
            start_from_label(record)
        if attestation.principal_id == self.policy.worker_principal_id:
            raise Forbidden("shared principal cannot prove manager origin")
        if attestation.role not in {"vibe", "project_manager"}:
            raise Forbidden("sender is not an assigning manager")
        key = self.policy.manager_keys.get(attestation.principal_id)
        if not key:
            raise Forbidden("sender is not an authorized manager principal")
        expected = _sign(key, attestation.signed_body())
        if not hmac.compare_digest(expected, attestation.signature):
            raise ApprovalInvalid("manager attestation signature is not valid")
        if attestation.decision not in {"assign", "cancel"}:
            raise Forbidden("unknown manager decision")
        if (
            attestation.owner != record.owner
            or attestation.repo != record.repo
            or attestation.issue_number != record.number
            or attestation.issue_node_id != record.node_id
            or attestation.base_sha != record.base_sha
            or attestation.updated_at != record.updated_at
        ):
            raise ApprovalInvalid("attestation does not match the GitHub task record")
        if attestation.decision == "assign" and record.state != "open":
            raise Forbidden("task record is not open")
        safe_relative(f"assignments/{record.number}")

    def _access(self, access: RepoAccess) -> None:
        if not access.pull or not access.push:
            raise Forbidden("repository access does not include pull and push")

    def _producer(self, record: GitHubTaskRecord, decision: ProducerDecision | None) -> None:
        name = f"{record.owner}/{record.repo}"
        if decision is None:
            if name in self.policy.plan_blocked_repos:
                raise Forbidden("plan excludes this repository and no producer decision overrides it")
            return
        if decision.principal_id != self.policy.producer_principal_id:
            raise Forbidden("producer decision is not from the configured producer")
        expected = _sign(self.policy.producer_key, decision.signed_body())
        if not hmac.compare_digest(expected, decision.signature):
            raise ApprovalInvalid("producer decision signature is not valid")
        if decision.statement in SECURITY_OVERRIDES:
            raise Forbidden("producer decisions do not override security controls")
        if decision.owner != record.owner or decision.repo != record.repo:
            raise Forbidden("producer decision is for a different repository")
        if decision.statement != "project_in_scope":
            raise Forbidden("unknown producer statement")

    def _ci_gate(self, record: GitHubTaskRecord, runners: tuple[RunnerView, ...]) -> str:
        if not runners:
            return "unavailable"
        decisions = tuple(runner_decision(runner, self.policy, record) for runner in runners)
        if "eligible" in decisions:
            return "eligible"
        for refused in ("hosted_refused", "inkbound_refused"):
            if refused in decisions:
                return refused
        return decisions[0]

    @staticmethod
    def _return(
        attestation: ManagerAttestation,
        status: str,
        head: str,
        pr_url: str,
        repairs: int,
        stages: tuple[StageRecord, ...],
    ) -> ManagerReturn:
        return ManagerReturn(
            manager_principal_id=attestation.principal_id,
            status=status,
            head_sha=head,
            pr_url=pr_url,
            repair_attempts=repairs,
            stages=stages,
            merged=False,
        )


def _evidence_body(
    record: GitHubTaskRecord, attestation: ManagerAttestation, head: str
) -> str:
    return (
        "Automatic candidate handoff for independent review.\n"
        f"Issue: {record.owner}/{record.repo}#{record.number}\n"
        f"Node: {record.node_id}\n"
        f"Base: {record.base_branch} {record.base_sha}\n"
        f"Head: {head}\n"
        f"Manager: {attestation.principal_id}\n"
        "Issue text is omitted. This pull request does not merge.\n"
    )


def evidence_directory(root: Path, relative: str) -> Path:
    """Create one evidence directory inside root or refuse the path."""

    safe_relative(relative)
    target = contained(root, root / relative)
    refuse_reparse(root)
    target.mkdir(parents=True, exist_ok=True)
    return target


def candidate_command(command: str) -> int:
    """CLI surface for the candidate. Install and activate always refuse."""

    if command == "show-contract":
        print(json.dumps(CAPABILITY_BOUNDARY, sort_keys=True))
        return 0
    if command in {"install-startup", "activate"}:
        print(
            json.dumps(
                {
                    "detail": "startup installer and activation remain disabled",
                    "error": "disabled",
                    "exit_code": 2,
                    "ok": False,
                },
                sort_keys=True,
            )
        )
        return 2
    raise Forbidden("unknown candidate command")
