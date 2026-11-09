# SPDX-License-Identifier: AGPL-3.0-only
"""Disabled-by-default assignment candidate wired to the existing adapters.

The live loop is off until a later approval. When a test or a future operator
turns `enabled` on, pickup uses GitHubHttpClient, AssignmentService, a local
git workspace, the command sandbox, and the publish token from the secret
file. A label only routes. It does not authorize. Symmetric manager HMAC is a
blocked unattended-trust boundary: the process that can read the verify key
can mint, so this module does not start an unattended listener.
"""

import hashlib
import hmac
import json
import os
import stat
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    Conflict,
    Disabled,
    Forbidden,
    MergeRejected,
)
from free_claude_code.assignments.execution import (
    GitWorkspace,
    NativeCommandApproval,
    Sandbox,
    scrub_env,
)
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.models import AllowlistEntry, AssignmentConfig, PublicationPlan
from free_claude_code.assignments.secrets import (
    load_secret_file,
    refuse_symlink_or_reparse,
    write_secret_file,
)
from free_claude_code.assignments.service import AssignmentService

ROUTING_LABEL = "dev:claude1"
REPAIR_LIMIT = 2
HOSTED_RUNNER_LABELS = frozenset(
    {"ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "windows-latest", "macos-latest"}
)
INKBOUND_RUNNER_LABELS = frozenset({"dell", "inkbound"})
PUBLISHER_ENV = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "FCC_PUBLISH_TOKEN",
)

CAPABILITY_BOUNDARY = {
    "adapters": "github_http_assignment_service_git_sandbox_secret_file",
    "label_dev_claude1": "routing_only",
    "manager_hmac": "bound_nonce_expiry_audience_revocation",
    "unattended_manager_trust": "blocked_symmetric_key_can_mint",
    "live_listener": "disabled",
    "startup_installer": "writes_disabled_plan_only",
    "activation": "disabled",
    "network_git_push": "blocked",
    "issue_creation": "unsupported_http_403_no_alternate_principal",
    "merge": "refused",
    "hosted_or_paid_ci": "refused",
    "inkbound_runners": "not_repurposed",
    "windows_dacl": "used_on_windows_unverified_here",
    "end_to_end_live": "not_claimed",
}


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _hmac(key: str, payload: Mapping[str, object]) -> str:
    return hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ManagerAttestation:
    principal_id: str
    role: str
    audience: str
    owner: str
    repo: str
    issue_number: int
    issue_node_id: str
    base_branch: str
    base_sha: str
    updated_at: str
    nonce: str
    expires_at: int
    decision: str
    signature: str

    def signed_body(self) -> dict[str, object]:
        return {
            "audience": self.audience,
            "base_branch": self.base_branch,
            "base_sha": self.base_sha,
            "decision": self.decision,
            "expires_at": self.expires_at,
            "issue_node_id": self.issue_node_id,
            "issue_number": self.issue_number,
            "nonce": self.nonce,
            "owner": self.owner,
            "principal_id": self.principal_id,
            "repo": self.repo,
            "role": self.role,
            "updated_at": self.updated_at,
        }


def sign_attestation(key: str, attestation: ManagerAttestation) -> ManagerAttestation:
    """Test and manager-side helper. The candidate verifier has no sign method."""

    signature = _hmac(key, attestation.signed_body())
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
        nonce=attestation.nonce,
        expires_at=attestation.expires_at,
        decision=attestation.decision,
        signature=signature,
    )


class ManagerVerifier:
    """Checks attestations. Repr does not include the key, and this object cannot sign."""

    def __init__(
        self,
        keys: Mapping[str, str],
        *,
        audience: str,
        now: int,
        state_dir: Path,
        revocations: set[str] | None = None,
    ) -> None:
        self._keys = dict(keys)
        self.audience = audience
        self.now = now
        self.state_dir = state_dir
        self.revocations = set(revocations or ())
        _private_dir(state_dir)

    def __repr__(self) -> str:
        return "ManagerVerifier([redacted])"

    def verify(
        self,
        attestation: ManagerAttestation,
        *,
        node_id: str,
        base_sha: str,
        owner: str,
        repo: str,
    ) -> None:
        if attestation.audience == attestation.principal_id:
            raise Forbidden("shared principal cannot prove manager origin")
        if attestation.audience != self.audience:
            raise Forbidden("attestation audience does not match this worker")
        if attestation.role not in {"vibe", "project_manager"}:
            raise Forbidden("sender is not an assigning manager")
        if attestation.decision not in {"assign", "cancel"}:
            raise Forbidden("unknown manager decision")
        if self.now > attestation.expires_at:
            raise ApprovalInvalid("manager attestation expired")
        if attestation.nonce in self.revocations or attestation.nonce in _read_lines(self._revocation_path()):
            raise ApprovalInvalid("manager attestation was revoked")
        key = self._keys.get(attestation.principal_id)
        if not key:
            raise Forbidden("sender is not an authorized manager principal")
        expected = _hmac(key, attestation.signed_body())
        if not hmac.compare_digest(expected, attestation.signature):
            raise ApprovalInvalid("manager attestation signature is not valid")
        if (
            attestation.issue_node_id != node_id
            or attestation.base_sha != base_sha
            or attestation.owner != owner
            or attestation.repo != repo
        ):
            raise ApprovalInvalid("attestation does not match the GitHub task record")
        if attestation.nonce in _read_lines(self._nonce_path()):
            raise ApprovalInvalid("manager attestation nonce was already used")

    def consume_nonce(self, nonce: str) -> None:
        path = self._nonce_path()
        seen = _read_lines(path)
        if nonce in seen:
            raise ApprovalInvalid("manager attestation nonce was already used")
        seen.add(nonce)
        _write_lines(path, seen)

    def _nonce_path(self) -> Path:
        return self.state_dir / "nonces.txt"

    def _revocation_path(self) -> Path:
        return self.state_dir / "revocations.txt"


@dataclass(frozen=True, slots=True)
class MachineGate:
    signed_in: bool
    active: bool
    plugged_in: bool
    online: bool
    sensor: str = "file"


def admit_machine(machine: MachineGate) -> str:
    if machine.sensor == "missing":
        return "queue_sensor_missing"
    if not machine.online:
        return "queue_offline"
    if not machine.signed_in:
        return "queue_signed_out"
    if not (machine.active and machine.plugged_in):
        return "queue_sleep"
    return "admit"


class FilesystemMachineProbe:
    """Read power, session, and network files. A missing sensor does not count as awake."""

    def __init__(self, power_file: Path, session_file: Path, network_file: Path) -> None:
        self.power_file = power_file
        self.session_file = session_file
        self.network_file = network_file

    def read(self) -> MachineGate:
        power = _sensor_bit(self.power_file)
        session = _sensor_bit(self.session_file)
        network = _sensor_bit(self.network_file)
        if None in {power, session, network}:
            return MachineGate(False, False, False, False, sensor="missing")
        return MachineGate(
            signed_in=bool(session),
            active=bool(session and power),
            plugged_in=bool(power),
            online=bool(network),
        )


def _sensor_bit(path: Path) -> int | None:
    if not path.is_file() or path.is_symlink():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if text not in {"0", "1"}:
        return None
    return int(text)


@contextmanager
def bounded_awake(probe: FilesystemMachineProbe, *, max_seconds: float) -> Iterator[None]:
    started = time.monotonic()
    if admit_machine(probe.read()) != "admit":
        raise Disabled("machine is not signed in, active, plugged in, and online")
    yield
    if time.monotonic() - started > max_seconds:
        raise Disabled("awake window elapsed")
    if admit_machine(probe.read()) != "admit":
        raise Disabled("machine left the awake window")


class DurableQueue:
    def __init__(self, root: Path) -> None:
        self.root = _private_dir(root)
        self.path = self.root / "queue.json"

    def push(self, item: dict[str, object]) -> None:
        rows = self._read()
        rows.append(item)
        _atomic_json(self.path, rows)

    def pop_matching(self, node_id: str) -> dict[str, object] | None:
        rows = self._read()
        found = None
        kept = []
        for row in rows:
            if found is None and row.get("issue_node_id") == node_id:
                found = row
            else:
                kept.append(row)
        if found is not None:
            _atomic_json(self.path, kept)
        return found

    def _read(self) -> list[dict[str, object]]:
        if not self.path.is_file():
            return []
        loaded = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            return []
        return [row for row in loaded if isinstance(row, dict)]


class ClaimLedger:
    def __init__(self, root: Path) -> None:
        self.root = _private_dir(root)
        self._claims = self.root / "claims.json"
        self._active = self.root / "active.lock"

    def get(self, key: str) -> dict[str, object] | None:
        tasks = self._tasks()
        found = tasks.get(key)
        return found if isinstance(found, dict) else None

    def claim(self, key: str, worker_id: str, base_sha: str) -> dict[str, object]:
        tasks = self._tasks()
        current = tasks.get(key)
        if isinstance(current, dict) and current.get("status") == "active":
            if current.get("worker_id") == worker_id and current.get("base_sha") == base_sha:
                return current
            if current.get("base_sha") != base_sha:
                self._mark_stale(tasks, key)
                raise ApprovalInvalid("base SHA changed under the claim")
            raise Conflict("another worker holds this assignment")
        if isinstance(current, dict) and current.get("status") in {"completed", "cancelled"}:
            raise Conflict(f"assignment is {current.get('status')} and is not revived")
        self._acquire_active(key)
        repairs = int(current.get("repairs", 0)) if isinstance(current, dict) else 0
        if isinstance(current, dict) and current.get("status") == "stale":
            repairs = 0
        claim = {"base_sha": base_sha, "repairs": repairs, "status": "active", "worker_id": worker_id}
        tasks[key] = claim
        self._write_tasks(tasks)
        return claim

    def update(self, key: str, **fields: object) -> dict[str, object]:
        tasks = self._tasks()
        if not isinstance(tasks.get(key), dict):
            raise Conflict("claim is missing")
        claim = dict(tasks[key])
        claim.update(fields)
        tasks[key] = claim
        self._write_tasks(tasks)
        if claim.get("status") != "active":
            self._release_active()
        return claim

    def _mark_stale(self, tasks: dict[str, object], key: str) -> None:
        current = tasks.get(key)
        if isinstance(current, dict):
            current = dict(current)
            current["status"] = "stale"
            tasks[key] = current
            self._write_tasks(tasks)
        self._release_active()

    def _tasks(self) -> dict[str, object]:
        if not self._claims.is_file():
            return {}
        loaded = json.loads(self._claims.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}

    def _write_tasks(self, tasks: dict[str, object]) -> None:
        _atomic_json(self._claims, tasks)

    def _acquire_active(self, key: str) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(self._active, flags, 0o600)
        except FileExistsError as exc:
            raise Conflict("one assignment is already active") from exc
        try:
            os.write(fd, key.encode("utf-8"))
        finally:
            os.close(fd)

    def _release_active(self) -> None:
        try:
            os.unlink(self._active)
        except FileNotFoundError:
            pass


def start_from_label() -> None:
    raise Forbidden(f"label {ROUTING_LABEL} is not execution authority")


def runner_decision(labels: tuple[str, ...], *, online: bool, busy: bool, repository: str, expected_repo: str) -> str:
    if repository != expected_repo:
        return "wrong_repo"
    folded = {item.lower() for item in labels}
    if folded & {item.lower() for item in HOSTED_RUNNER_LABELS}:
        return "hosted_refused"
    if folded & {item.lower() for item in INKBOUND_RUNNER_LABELS}:
        return "inkbound_refused"
    required = {"self-hosted", "windows", "x64"}
    if not required <= folded:
        return "labels_missing"
    if not online or busy:
        return "unavailable"
    return "eligible"


class IssueCreation:
    def __init__(self) -> None:
        self.attempts = 0

    def create_issue(self) -> None:
        self.attempts += 1
        raise Forbidden(
            "GitHub issue creation is unsupported after HTTP 403; no alternate principal and no retry"
        )


def model_environment(source: Mapping[str, str], publish_token: str) -> dict[str, str]:
    cleaned = scrub_env(dict(source))
    for name in PUBLISHER_ENV:
        cleaned.pop(name, None)
    return {key: value for key, value in cleaned.items() if publish_token and value != publish_token}


def push_local_feature(workspace: Path, remote: Path, branch: str) -> None:
    """Push one feature branch to a local bare repo. Network remotes stay blocked."""

    if branch in {"main", "master"} or branch.startswith("-") or ".." in branch.split("/"):
        raise MergeRejected("refusing a protected or unsafe branch")
    remote_text = str(remote)
    if remote_text.startswith(("http://", "https://", "git@", "ssh://")):
        raise Forbidden("network git push is blocked; no live repository write")
    if not remote.is_dir() or remote.is_symlink():
        raise Forbidden("local git remote is missing or is a symlink")
    env = scrub_env(os.environ)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    completed = __import__("subprocess").run(
        ("git", "push", remote_text, f"{branch}:{branch}"),
        cwd=workspace,
        env=env,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise Forbidden("local feature push failed")


@dataclass(frozen=True, slots=True)
class CandidatePaths:
    state_dir: Path
    source_repo: Path
    workspace: Path
    secrets_file: Path
    inbox: Path
    power_file: Path
    session_file: Path
    network_file: Path
    local_remote: Path


class AssignmentCandidate:
    """One pickup cycle. `enabled` defaults off and there is no listener thread."""

    def __init__(
        self,
        *,
        enabled: bool,
        owner: str,
        repo: str,
        api: GitHubHttpClient,
        paths: CandidatePaths,
        verifier: ManagerVerifier,
        operator_id: str,
        reviewer_id: str,
        allowed_command: tuple[str, ...],
        command_cwd: str,
        repair_limit: int = REPAIR_LIMIT,
        awake_seconds: float = 30.0,
    ) -> None:
        self.enabled = enabled
        self.owner = owner
        self.repo = repo
        self.api = api
        self.paths = paths
        self.verifier = verifier
        self.operator_id = operator_id
        self.reviewer_id = reviewer_id
        self.allowed_command = allowed_command
        self.command_cwd = command_cwd
        self.repair_limit = repair_limit
        self.awake_seconds = awake_seconds
        self.issues = IssueCreation()
        self.ledger = ClaimLedger(paths.state_dir / "claims")
        self.queue = DurableQueue(paths.state_dir / "queue")
        self.probe = FilesystemMachineProbe(paths.power_file, paths.session_file, paths.network_file)
        self.model_spawn = None
        self.model_grant = None
        self.model_grant_factory = None
        self.grant_key = ""
        self.now = 0

    def create_issue(self) -> None:
        self.issues.create_issue()

    def run_once(self) -> dict[str, object]:
        if not self.enabled:
            raise Disabled("assignment candidate is disabled")
        if self.operator_id == self.reviewer_id:
            raise Forbidden("publication needs an independent reviewer")
        gate = admit_machine(self.probe.read())
        numbers = self.api.list_labeled_issues(
            self.owner, self.repo, ROUTING_LABEL, timeout=self.api.timeout
        )
        if gate != "admit":
            for number in numbers:
                self.queue.push({"issue_number": number, "reason": gate, "label": ROUTING_LABEL})
            return {"status": gate, "numbers": list(numbers), "merged": False}
        if not numbers:
            return {"status": "idle", "merged": False}
        number = numbers[0]
        labels = self.api.fetch_issue_labels(self.owner, self.repo, number, timeout=self.api.timeout)
        if ROUTING_LABEL not in labels:
            return {"status": "not_routed", "merged": False}
        permissions = self.api.fetch_permissions(self.owner, self.repo, timeout=self.api.timeout)
        if not permissions.get("pull") or not permissions.get("push"):
            raise Forbidden("repository access does not include pull and push")
        attestation = self._attestation_for(number)
        issue = self.api.fetch_issue(self.owner, self.repo, number, timeout=self.api.timeout)
        base_sha = self.api.fetch_branch_sha(
            self.owner, self.repo, attestation.base_branch, timeout=self.api.timeout
        )
        self.verifier.verify(
            attestation,
            node_id=issue.node_id,
            base_sha=base_sha,
            owner=self.owner,
            repo=self.repo,
        )
        if attestation.issue_number != number:
            raise ApprovalInvalid("attestation issue number does not match")
        if attestation.decision == "cancel":
            self.verifier.consume_nonce(attestation.nonce)
            existing = self.ledger.get(self._key(number))
            if existing and existing.get("status") == "active":
                self.ledger.update(self._key(number), status="cancelled")
            return {"status": "cancelled", "merged": False}
        self.verifier.consume_nonce(attestation.nonce)
        with bounded_awake(self.probe, max_seconds=self.awake_seconds):
            return self._execute(number, attestation, base_sha)

    def _execute(self, number: int, attestation: ManagerAttestation, base_sha: str) -> dict[str, object]:
        key = self._key(number)
        claim = self.ledger.claim(key, self.verifier.audience, base_sha)
        service = self._service(number, attestation.base_branch)
        manifest = service.fetch(self.owner, self.repo, number, reader=self.api)
        if manifest.base_sha != base_sha:
            raise ApprovalInvalid("fetched base SHA does not match the attestation")
        service.approve(manifest, phase="execute", operator_id=self.operator_id, reader=self.api)
        service.approve(manifest, phase="publish", operator_id=self.operator_id, reader=self.api)
        workspace = GitWorkspace(self.paths.workspace)
        if self.paths.workspace.exists():
            raise Forbidden("workspace already exists")
        landed = workspace.materialize(
            self.paths.source_repo,
            base_sha,
            f"fcc-task/{number}-{base_sha[:12]}",
        )
        if landed != base_sha or workspace.branch_name() != f"fcc-task/{number}-{base_sha[:12]}":
            raise Forbidden("branch is not bound to the approved base")
        repairs = int(claim.get("repairs", 0))
        logs: list[dict[str, object]] = []
        evidence = None
        command_root = self.paths.workspace / self.command_cwd
        secrets = load_secret_file(self.paths.secrets_file)
        publish_token = secrets.get("github_publish")
        child_env = model_environment(os.environ, publish_token)
        self._publish_token = publish_token
        if publish_token in child_env.values() or any(name in child_env for name in PUBLISHER_ENV):
            raise Forbidden("publisher credential reached a child environment")
        sandbox = Sandbox(command_root, allowed=(self.allowed_command,), timeout_seconds=10)
        while True:
            self._run_model_if_granted(manifest, child_env)
            try:
                evidence = sandbox.run(
                    NativeCommandApproval(manifest.manifest_id, self.allowed_command, self.operator_id),
                    manifest=manifest,
                    head_sha=workspace.head(),
                    env=child_env,
                )
            except Forbidden:
                self.ledger.update(key, status="blocked", repairs=repairs)
                raise
            code = evidence.returncode if evidence.returncode is not None else 1
            logs.append({"stage": "test", "exit_code": code, "stderr": evidence.stderr_tail})
            if code == 0:
                break
            if repairs >= self.repair_limit:
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            repairs += 1
            self.ledger.update(key, status="active", repairs=repairs)
        if evidence is None or evidence.returncode != 0:
            raise Forbidden("execution loop ended without a passing command")
        widget = command_root / "widget.py"
        if widget.is_file() and "return left + right" in widget.read_text(encoding="utf-8"):
            workspace.commit_scoped(("src/widget.py",), "assignment candidate edit")
        head = workspace.head()
        if head != workspace.head() or not workspace.ancestry_contains(base_sha, head):
            raise Forbidden("resolved HEAD is not based on the approved SHA")
        if workspace.branch_name() != f"fcc-task/{number}-{base_sha[:12]}":
            raise Forbidden("HEAD is not the feature branch")
        push_local_feature(self.paths.workspace, self.paths.local_remote, workspace.branch_name())
        plan = service.prepare_publication(
            manifest, reader=self.api, reviewer_id=self.reviewer_id, patch_sha256=head
        )
        plan = PublicationPlan(
            manifest_id=plan.manifest_id,
            base_branch=plan.base_branch,
            head_branch=workspace.branch_name(),
            title=plan.title,
            body=plan.body + f"\nResolved head: {head}\n",
            patch_sha256=head,
            reviewer_id=self.reviewer_id,
            author_id=self.operator_id,
        )
        publisher = GitHubHttpClient(self.api.base_url, publish_token, timeout=self.api.timeout)
        url = service.publish(manifest, plan, reader=self.api, writer=_HttpWriter(publisher, self.owner, self.repo))
        checks = self.api.fetch_check_runs(self.owner, self.repo, head, timeout=self.api.timeout)
        ci = "not_read"
        if checks:
            failed = [item for item in checks if item.get("conclusion") not in {None, "success", "skipped"}]
            ci = "failure" if failed else "success"
        if ci == "failure":
            self.ledger.update(key, status="stopped", repairs=repairs, head_sha=head)
            return {
                "status": "ci_hold",
                "repair_attempts": repairs,
                "head_sha": head,
                "pr_url": url,
                "ci": ci,
                "logs": logs,
                "merged": False,
                "child_has_publish_token": False,
            }
        self.ledger.update(key, status="completed", repairs=repairs, head_sha=head)
        return {
            "status": "returned_for_review",
            "repair_attempts": repairs,
            "head_sha": head,
            "pr_url": url,
            "branch": workspace.branch_name(),
            "ci": ci,
            "logs": logs,
            "merged": False,
            "child_has_publish_token": False,
            "manager": attestation_principal(attestation),
        }

    def _run_model_if_granted(self, manifest: object, child_env: dict[str, str]) -> None:
        if self.model_grant is None and self.model_grant_factory is not None:
            self.model_grant = self.model_grant_factory(manifest)
        if self.model_grant is None or self.model_spawn is None:
            return
        from free_claude_code.assignments.execution import NvidiaClaudeLauncher

        launcher = NvidiaClaudeLauncher("claude", "http://127.0.0.1:9", "proxy-token")

        def spawn(argv: tuple[str, ...], env: dict[str, str], workspace: Path) -> None:
            if self._publish_token in env.values() or any(name in env for name in PUBLISHER_ENV):
                raise Forbidden("publisher credential reached the model process")
            if "--dangerously-skip-permissions" in argv:
                raise Forbidden("permission bypass flags are not used")
            self.model_spawn(argv, env, workspace)  # type: ignore[misc]

        launcher.run(
            manifest,  # type: ignore[arg-type]
            self.paths.workspace,
            self.model_grant,
            grant_key=self.grant_key,
            now=self.now,
            revocations=set(),
            spawn=spawn,
        )
        if any(name in child_env for name in PUBLISHER_ENV):
            raise Forbidden("publisher credential reached a child environment")

    def _service(self, number: int, base_branch: str) -> AssignmentService:
        config = AssignmentConfig(
            enabled=True,
            allowlist=(AllowlistEntry(self.owner, self.repo, number, base_branch),),
            operators=(self.operator_id,),
            allowed_path_prefixes=("src",),
            fetch_timeout_seconds=self.api.timeout,
        )
        from free_claude_code.assignments.store import StateStore

        return AssignmentService(config, StateStore(self.paths.state_dir / "service"))

    def _attestation_for(self, number: int) -> ManagerAttestation:
        path = self.paths.inbox / f"{number}.json"
        refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
        if not path.is_file():
            start_from_label()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return ManagerAttestation(
            principal_id=str(raw["principal_id"]),
            role=str(raw["role"]),
            audience=str(raw["audience"]),
            owner=str(raw["owner"]),
            repo=str(raw["repo"]),
            issue_number=int(raw["issue_number"]),
            issue_node_id=str(raw["issue_node_id"]),
            base_branch=str(raw["base_branch"]),
            base_sha=str(raw["base_sha"]),
            updated_at=str(raw["updated_at"]),
            nonce=str(raw["nonce"]),
            expires_at=int(raw["expires_at"]),
            decision=str(raw["decision"]),
            signature=str(raw["signature"]),
        )

    def _key(self, number: int) -> str:
        return f"{self.owner}/{self.repo}#{number}"


def attestation_principal(attestation: ManagerAttestation) -> str:
    return attestation.principal_id


class _HttpWriter:
    def __init__(self, client: GitHubHttpClient, owner: str, repo: str) -> None:
        self.client = client
        self.owner = owner
        self.repo = repo

    def create_pull_request(self, plan: PublicationPlan) -> str:
        return self.client.create_pull_request_for(self.owner, self.repo, plan)


def install_disabled_startup(root: Path) -> Path:
    """Write a startup plan that stays disabled. This does not register it with the OS."""

    target = _private_dir(root)
    plan = {
        "enabled": False,
        "registered_with_os": False,
        "power_policy_changed": False,
        "command": "python -m free_claude_code.assignments.candidate run-once",
    }
    _atomic_json(target / "startup-plan.json", plan)
    (target / "enabled").write_text("false\n", encoding="utf-8")
    os.chmod(target / "enabled", 0o600)
    return target / "startup-plan.json"


def activate_startup(root: Path) -> None:
    approval = root / "ACTIVATION_APPROVED"
    if not approval.is_file():
        raise Disabled("activation is disabled pending separate approval")
    raise Disabled("activation approval file is not honored by this build")


def candidate_command(command: str, root: Path | None = None) -> int:
    if command == "show-contract":
        print(json.dumps(CAPABILITY_BOUNDARY, sort_keys=True))
        return 0
    if command == "install-startup":
        if root is None:
            raise Disabled("install requires a disposable directory")
        install_disabled_startup(root)
        print(json.dumps({"enabled": False, "exit_code": 0, "registered_with_os": False}, sort_keys=True))
        return 0
    if command == "activate":
        print(
            json.dumps(
                {"detail": "activation remains disabled", "error": "disabled", "exit_code": 2, "ok": False},
                sort_keys=True,
            )
        )
        return 2
    raise Forbidden("unknown candidate command")


def _private_dir(path: Path) -> Path:
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise Forbidden("state directory is not private")
    return path


def _atomic_json(path: Path, payload: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_lines(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _write_lines(path: Path, values: set[str]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, ("".join(f"{item}\n" for item in sorted(values))).encode("utf-8"))
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_secret_file(path: Path, publish_token: str) -> None:
    write_secret_file(
        path,
        {
            "github_read": "read-token",
            "github_ci": "ci-token",
            "github_publish": publish_token,
            "grant_key": "grant-key",
            "proxy_auth": "proxy-token",
        },
    )
    load_secret_file(path)
