# SPDX-License-Identifier: AGPL-3.0-only
"""Disabled-by-default assignment candidate wired to the existing adapters.

The live loop is off until a later approval. When a test or a future operator
turns `enabled` on, pickup uses GitHubHttpClient, AssignmentService, a local
git workspace, the command sandbox, and a separate publisher process.
The configured waiting label only routes. A manager Ed25519 signature
authorizes both execute and publish. This module verifies manager keys and
cannot mint them. Each install loads its own worker identity.
"""

import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from free_claude_code.assignments import machine_stats
from free_claude_code.assignments.ed25519_verify import verify_ed25519
from free_claude_code.assignments.handoff import actor_label, assert_handoff_label
from free_claude_code.assignments.identity import WorkerIdentity, default_worker_identity
from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    Conflict,
    Disabled,
    Forbidden,
    MergeRejected,
    ModelSessionFailed,
    TimedOut,
)
from free_claude_code.assignments.execution import (
    GitWorkspace,
    NativeCommandApproval,
    Sandbox,
    failed_rerun_command,
    resolve_program,
    scrub_env,
)
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.grants import load_grant, load_revocations
from free_claude_code.assignments.models import AllowlistEntry, AssignmentConfig, PublicationPlan
from free_claude_code.assignments.private_io import atomic_write_private, write_private_bytes
from free_claude_code.assignments.secrets import (
    load_secret_file,
    refuse_symlink_or_reparse,
    write_secret_file,
)
from free_claude_code.assignments.service import AssignmentService

_DEFAULT_WORKER = default_worker_identity()
ACTOR_NAME = _DEFAULT_WORKER.actor_name
ACTOR_BARE = _DEFAULT_WORKER.bare_name
DEFAULT_WAITING_LABEL = _DEFAULT_WORKER.waiting_label
COMMENT_SUFFIX = _DEFAULT_WORKER.comment_suffix()
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
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "SLACK_API_TOKEN",
)

CAPABILITY_BOUNDARY = {
    "adapters": "github_http_assignment_service_git_sandbox_secret_file",
    "actor": ACTOR_NAME,
    "routing_label": DEFAULT_WAITING_LABEL,
    "label_is_authority": False,
    "manager_signatures": "ed25519_public_key_only",
    "text_signature": "convention_only_not_authority",
    "dev_label_family": "refused",
    "live_listener": "disabled",
    "startup_installer": "writes_disabled_plan_only",
    "logon_task": "opt_in_per_user_least_privilege_not_registered_by_install",
    "wake": "ac_only_system_required_no_display_no_powercfg",
    "activation": "live_only_when_worker_json_and_activation_record",
    "network_git_push": "disabled_until_publisher_enabled_one_https_origin",
    "manager_set": "config_file_of_pinned_public_keys",
    "manager_attestation": "one_signature_covers_execute_and_publish",
    "worker_identity": "per_install_config",
    "handoff_actors": "briefing_set_plus_claudeN_manager_map_is_config",
    "slack_handoff": "disabled_bot_token_one_channel_chat_post_message",
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


def _hmac(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


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
    task_id: str
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
            "task_id": self.task_id,
            "updated_at": self.updated_at,
        }


class ManagerVerifier:
    """Checks attestations against a configured set of public keys. It cannot sign."""

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        roles: Mapping[str, str],
        display_names: Mapping[str, str],
        audience: str,
        now: int,
        state_dir: Path,
        revocations: set[str] | None = None,
        github_logins: Mapping[str, str] | None = None,
        interim_until: Mapping[str, str] | None = None,
        handoff_actors: Mapping[str, str] | None = None,
    ) -> None:
        self._keys = dict(keys)
        self._roles = dict(roles)
        self._display_names = dict(display_names)
        self._github_logins = dict(github_logins or {})
        self._interim_until = dict(interim_until or {})
        self._handoff_actors = dict(handoff_actors or {})
        self.audience = audience
        self.now = now
        self.state_dir = state_dir
        self.revocations = set(revocations or ())
        _private_dir(state_dir)

    @property
    def principal_ids(self) -> tuple[str, ...]:
        return tuple(self._keys)

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
        updated_at: str,
    ) -> None:
        if attestation.audience == attestation.principal_id:
            raise Forbidden("shared principal cannot prove manager origin")
        if attestation.audience != self.audience:
            raise Forbidden("attestation audience does not match this worker")
        if attestation.decision not in {"assign", "cancel"}:
            raise Forbidden("unknown manager decision")
        if _interim_expired(self.interim_until(attestation.principal_id), self.now):
            raise ApprovalInvalid("manager key is past interim_until")
        if self.now > attestation.expires_at:
            raise ApprovalInvalid("manager attestation expired")
        if attestation.nonce in self.revocations or attestation.nonce in _read_lines(self._revocation_path()):
            raise ApprovalInvalid("manager attestation was revoked")
        public_key = self._keys.get(attestation.principal_id)
        expected_role = self._roles.get(attestation.principal_id)
        if not public_key or expected_role is None:
            raise Forbidden("sender is not an authorized manager principal")
        if attestation.role != expected_role or attestation.role not in {"vibe", "project_manager"}:
            raise Forbidden("sender is not an assigning manager")
        try:
            signature = bytes.fromhex(attestation.signature)
        except ValueError as exc:
            raise ApprovalInvalid("manager attestation signature is not valid") from exc
        if not verify_ed25519(public_key, _canonical(attestation.signed_body()), signature):
            raise ApprovalInvalid("manager attestation signature is not valid")
        if (
            attestation.issue_node_id != node_id
            or attestation.base_sha != base_sha
            or attestation.owner != owner
            or attestation.repo != repo
            or attestation.updated_at != updated_at
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

    def display_name(self, principal_id: str) -> str:
        return self._display_names.get(principal_id, principal_id)

    def interim_until(self, principal_id: str) -> str:
        return self._interim_until.get(principal_id, "")

    def public_keys(self) -> tuple[bytes, ...]:
        return tuple(self._keys.values())

    def handoff_for(self, principal_id: str) -> tuple[str, str]:
        actor = self._handoff_actors.get(principal_id, "")
        if not actor:
            raise Forbidden("signing manager has no handoff actor")
        label = actor_label(actor)
        assert_handoff_label(label)
        return actor, label


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
    from free_claude_code.assignments.wake import PluggedInWake

    with PluggedInWake():
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
        if "issue_number" not in item or "issue_node_id" not in item:
            raise Forbidden("queue item needs an issue number and node id")
        rows = self._read()
        rows.append(item)
        self._write(rows)

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
            self._write(kept)
        return found

    def _read(self) -> list[dict[str, object]]:
        if not self.path.is_file():
            return []
        loaded = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict) or not isinstance(loaded.get("items"), list):
            raise Forbidden("queue integrity check failed")
        items = [row for row in loaded["items"] if isinstance(row, dict)]
        expected = _hmac(self._integrity_key(), _canonical({"items": items}))
        if not hmac.compare_digest(str(loaded.get("mac", "")), expected):
            raise Forbidden("queue integrity check failed")
        return items

    def _write(self, items: list[dict[str, object]]) -> None:
        payload = {"items": items, "mac": _hmac(self._integrity_key(), _canonical({"items": items}))}
        _atomic_json(self.path, payload)

    def _integrity_key(self) -> bytes:
        path = self.root / "integrity.key"
        if path.is_file():
            return path.read_bytes()
        key = os.urandom(32)
        write_private_bytes(path, key, exclusive=True)
        return key


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
        if not isinstance(loaded, dict) or not isinstance(loaded.get("tasks"), dict):
            raise Forbidden("claim ledger is not intact")
        expected = _hmac(self._integrity_key(), _canonical(loaded["tasks"]))
        if not hmac.compare_digest(str(loaded.get("mac", "")), expected):
            raise Forbidden("claim ledger integrity check failed")
        return loaded["tasks"]

    def _write_tasks(self, tasks: dict[str, object]) -> None:
        payload = {"mac": _hmac(self._integrity_key(), _canonical(tasks)), "tasks": tasks}
        _atomic_json(self._claims, payload)

    def _integrity_key(self) -> bytes:
        path = self.root / "integrity.key"
        if path.is_file():
            return path.read_bytes()
        key = os.urandom(32)
        write_private_bytes(path, key, exclusive=True)
        return key

    def _acquire_active(self, key: str) -> None:
        payload = f"{os.getpid()}\n{int(time.time()) + 120}\n{key}\n".encode("utf-8")
        try:
            write_private_bytes(self._active, payload, exclusive=True)
        except FileExistsError as exc:
            if not self._lock_is_stale():
                raise Conflict("one assignment is already active") from exc
            self._release_active()
            write_private_bytes(self._active, payload, exclusive=True)

    def _lock_is_stale(self) -> bool:
        try:
            text = self._active.read_text(encoding="utf-8")
        except OSError:
            return True
        lines = text.splitlines()
        if len(lines) < 2:
            return True
        try:
            pid = int(lines[0])
            expiry = int(lines[1])
        except ValueError:
            return True
        if time.time() > expiry or not _pid_alive(pid):
            return True
        return False

    def _release_active(self) -> None:
        try:
            os.unlink(self._active)
        except FileNotFoundError:
            pass


def assert_routing_label(label: str) -> None:
    if label.startswith("dev:") or label.startswith("status:"):
        raise Forbidden("refusing to search or create a dev or status label")
    if not label.startswith("waiting:"):
        raise Forbidden("routing label must be a waiting label")


def start_from_label() -> None:
    raise Forbidden("a waiting label is not execution authority")


def assert_independent_reviewer(
    *, author_login: str, pusher_login: str = "", logins: frozenset[str]
) -> None:
    if author_login in logins or pusher_login in logins:
        raise Forbidden("refusing to review a pull request this actor authored or pushed")


def assert_reviewer_is_not_author(*, author_login: str, reviewer_login: str) -> None:
    if author_login and author_login == reviewer_login:
        raise Forbidden("author cannot review their own pull request")


_RUN_RECORD = Path("test-results") / ".last-run.json"


def _remove_stale_run_record(command_root: Path) -> bool:
    """Remove a failed-test record left over from before the next check pass.

    EXEC-RETRY-01 repair (Cody HOLD on PR #36): a record that already
    exists when a pass starts cannot be told apart from one the pass
    itself writes, so immediately before each check invocation the slate
    is cleared and only a record that appears afterwards is trusted as
    that pass's own. Returns True when a pre-existing record was removed;
    the removal is recorded in the stage log by the caller.
    """

    try:
        (command_root / _RUN_RECORD).unlink()
    except OSError:
        return False
    return True


def _tracked_run_record(
    workspace: GitWorkspace, command_root: Path, record_relative: str
) -> bytes | None:
    """Bytes of a pre-existing failed-test record that is a TRACKED file.

    EXEC-RETRY-01 repair 2 (Cody HOLD #2 on PR #36): a tracked record
    is never the worker's to delete — unlinking one puts a deletion the
    model never made into the workspace diff, where change-scope
    validation can sweep it into the published commit. Returns the
    record's current bytes when the file exists and git tracks it, so
    the caller can leave it in place and decide after the pass whether
    the pass rewrote it; None when there is no tracked record (the
    caller then clears the slate as usual).
    """

    if not (command_root / _RUN_RECORD).exists():
        return None
    if not workspace.is_tracked(record_relative):
        return None
    try:
        return (command_root / _RUN_RECORD).read_bytes()
    except OSError:
        return None


def _record_written_by_pass(command_root: Path, previous: bytes) -> bool:
    """True when the record on disk now differs from the tracked bytes
    captured before the pass — the pass rewrote the record, so its
    content is this pass's own. Byte-identical content cannot be told
    apart from the stale record and stays untrusted."""

    try:
        return (command_root / _RUN_RECORD).read_bytes() != previous
    except OSError:
        return False


def _recorded_failed_tests(command_root: Path) -> tuple[str, ...]:
    """Failed test ids the check tool recorded for the pass that just failed.

    Playwright writes test-results/.last-run.json under its working
    directory on every run; its failedTests list is exactly what
    --last-failed would re-run. A missing or malformed record means the
    failure was not a recorded test failure, and the caller keeps the
    existing behavior for it.
    """

    try:
        loaded = json.loads((command_root / _RUN_RECORD).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    if not isinstance(loaded, dict) or not isinstance(loaded.get("failedTests"), list):
        return ()
    return tuple(item for item in loaded["failedTests"] if isinstance(item, str))


def _comment_payload(body: str) -> bytes:
    lines = [
        line
        for line in body.splitlines()
        if not line.startswith("SIGNATURE:") and not line.strip().startswith("— ")
    ]
    return "\n".join(lines).strip().encode("utf-8")


def _signature_from_comment(body: str) -> bytes | None:
    for line in body.splitlines():
        if not line.startswith("SIGNATURE:"):
            continue
        try:
            raw = bytes.fromhex(line.split(":", 1)[1].strip())
        except ValueError:
            return None
        return raw if len(raw) == 64 else None
    return None


def _login(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("login", ""))
    return ""


def _review_manifest(head_sha: str) -> object:
    from free_claude_code.assignments.models import ModelProvenance, Scope, TaskManifest

    return TaskManifest(
        task_key="review",
        owner="local",
        repo="review",
        issue_number=0,
        issue_revision="0" * 64,
        title_redacted="review",
        base_branch="dev",
        base_sha=head_sha,
        scope=Scope(("src",), 200_000),
        model=ModelProvenance(),
    )


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
    directory = Path(workspace).expanduser().resolve(strict=False)
    if not directory.is_dir():
        raise Forbidden("local feature push cwd is not a directory")
    completed = __import__("subprocess").run(
        (resolve_program("git"), "push", str(Path(remote).expanduser().resolve()), f"{branch}:{branch}"),
        cwd=str(directory),
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
        allowed_path_prefixes: tuple[str, ...] = ("src",),
        command_timeout_seconds: float = 10.0,
        allow_failed_test_rerun: bool = False,
        setup_command: tuple[str, ...] | None = None,
        grants_dir: Path | None = None,
        model_proxy_base_url: str = "http://127.0.0.1:8082",
        repair_limit: int = REPAIR_LIMIT,
        awake_seconds: float = 7200.0,  # AWAKE-01: sane default matched to live.AWAKE_SECONDS_DEFAULT; the old 30s default masked run results
        identity: WorkerIdentity | None = None,
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
        self.allowed_path_prefixes = tuple(allowed_path_prefixes)
        self.command_timeout_seconds = float(command_timeout_seconds)
        # EXEC-RETRY-01: the failed-test re-run inside the check stage is
        # authorized only by the explicit runtime opt-in
        # (allow_failed_test_rerun in runtime.json, absent/off by
        # default — Producer decision, Casey, 2026-11-11). Without it the
        # check stage behaves exactly as it did before the feature.
        self.allow_failed_test_rerun = bool(allow_failed_test_rerun)
        self.setup_command = tuple(setup_command) if setup_command else None
        self.grants_dir = grants_dir
        self.model_proxy_base_url = model_proxy_base_url
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
        self.clock = time.time
        self.identity = identity or default_worker_identity()
        self.waiting_label = self.identity.waiting_label
        self.publish_enabled = False
        self.publish_origin = ""
        self.publish_ca_file = None
        self.slack_api_base = ""
        self.verdict_key_file = self.identity.verdict_key_file

    def create_issue(self) -> None:
        self.issues.create_issue()

    def run_once(self) -> dict[str, object]:
        if not self.enabled:
            raise Disabled("assignment candidate is disabled")
        if self.operator_id == self.reviewer_id:
            raise Forbidden("publication needs an independent reviewer")
        assert_routing_label(self.waiting_label)
        gate = admit_machine(self.probe.read())
        labeled = self.api.list_labeled_issues(
            self.owner, self.repo, self.waiting_label, timeout=self.api.timeout
        )
        if gate != "admit":
            for number in labeled:
                issue = self.api.fetch_issue(self.owner, self.repo, number, timeout=self.api.timeout)
                self.queue.push(
                    {
                        "issue_number": number,
                        "issue_node_id": issue.node_id,
                        "reason": gate,
                        "label": self.waiting_label,
                    }
                )
            return {"status": gate, "numbers": list(labeled), "merged": False}
        numbers = labeled or self._inbox_issue_numbers()
        if not numbers:
            return {"status": "idle", "merged": False}
        number = numbers[0]
        labels = self.api.fetch_issue_labels(self.owner, self.repo, number, timeout=self.api.timeout)
        issue = self.api.fetch_issue(self.owner, self.repo, number, timeout=self.api.timeout)
        attestation = self._attestation_for(number)
        base_sha = self.api.fetch_branch_sha(
            self.owner, self.repo, attestation.base_branch, timeout=self.api.timeout
        )
        route = self._route(number, labels, self._route_sha(number, base_sha))
        if route == "absent":
            return {"status": "not_routed", "merged": False}
        if route == "stale":
            return {"status": "stale_head", "merged": False}
        self.queue.pop_matching(issue.node_id)
        permissions = self.api.fetch_permissions(self.owner, self.repo, timeout=self.api.timeout)
        if not permissions.get("pull") or not permissions.get("push"):
            raise Forbidden("repository access does not include pull and push")
        self.verifier.verify(
            attestation,
            node_id=issue.node_id,
            base_sha=base_sha,
            owner=self.owner,
            repo=self.repo,
            updated_at=issue.updated_at,
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
        # One verified manager attestation covers both phases. The two records
        # share that principal. This module does not mint a second signature.
        service.approve(manifest, phase="execute", operator_id=attestation.principal_id, reader=self.api)
        service.approve(manifest, phase="publish", operator_id=attestation.principal_id, reader=self.api)
        workspace = GitWorkspace(self.paths.workspace)
        if self.paths.workspace.exists():
            raise Forbidden("workspace already exists")
        landed = workspace.materialize(
            self.paths.source_repo,
            base_sha,
            self.identity.feature_branch(attestation.task_id),
        )
        if landed != base_sha or workspace.branch_name() != self.identity.feature_branch(attestation.task_id):
            raise Forbidden("branch is not bound to the approved base")
        repairs = int(claim.get("repairs", 0))
        logs: list[dict[str, object]] = []
        evidence = None
        command_root = self.paths.workspace / self.command_cwd
        record_relative = (Path(self.command_cwd) / _RUN_RECORD).as_posix()
        secrets = load_secret_file(self.paths.secrets_file)
        publish_token = secrets.get("github_publish")
        child_env = model_environment(os.environ, publish_token)
        self._publish_token = publish_token
        if publish_token in child_env.values() or any(name in child_env for name in PUBLISHER_ENV):
            raise Forbidden("publisher credential reached a child environment")
        # EXEC-RETRY-01: only when the explicit runtime opt-in authorizes
        # the failed-test re-run does the check sandbox also admit exactly
        # one derived argv — the configured command plus --last-failed,
        # built by trusted code (failed_rerun_command) from the approved
        # command. Without the opt-in the derived argv is not even
        # admitted. Nothing else is admitted either way; vet_command still
        # exact-matches every call.
        check_commands = (self.allowed_command,)
        if self.allow_failed_test_rerun:
            check_commands = (self.allowed_command, failed_rerun_command(self.allowed_command))
        sandbox = Sandbox(
            command_root,
            allowed=check_commands,
            timeout_seconds=self.command_timeout_seconds,
        )
        bound_setup = tuple(manifest.scope.setup_command)
        if tuple(self.setup_command or ()) != bound_setup:
            # The manifest is the approval record: its id binds the exact
            # setup argv through the scope fingerprint. A candidate whose
            # configured setup differs from the bound one must not run
            # either command.
            self.ledger.update(key, status="blocked", repairs=repairs)
            raise Forbidden("setup command does not match the approved manifest")
        if bound_setup:
            setup_sandbox = Sandbox(
                command_root, allowed=(bound_setup,), timeout_seconds=self.command_timeout_seconds
            )
            setup_started = time.monotonic()
            try:
                setup_evidence = setup_sandbox.run(
                    NativeCommandApproval(manifest.manifest_id, bound_setup, attestation.principal_id),
                    manifest=manifest,
                    head_sha=workspace.head(),
                    env=child_env,
                )
            except Forbidden:
                self.ledger.update(key, status="blocked", repairs=repairs)
                raise
            except TimedOut:
                logs.append(
                    {
                        "stage": "setup",
                        "exit_code": None,
                        "stderr": "",
                        "error": "timed_out",
                        "duration_seconds": time.monotonic() - setup_started,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {"status": "stopped", "repair_attempts": repairs, "logs": logs}
            except OSError:
                logs.append(
                    {
                        "stage": "setup",
                        "exit_code": None,
                        "stderr": "",
                        "error": "start_failed",
                        "duration_seconds": time.monotonic() - setup_started,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {"status": "stopped", "repair_attempts": repairs, "logs": logs}
            setup_code = setup_evidence.returncode if setup_evidence.returncode is not None else 1
            logs.append(
                {
                    "stage": "setup",
                    "exit_code": setup_code,
                    "stderr": setup_evidence.stderr_tail,
                    "duration_seconds": time.monotonic() - setup_started,
                }
            )
            if setup_code != 0:
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {"status": "stopped", "repair_attempts": repairs, "logs": logs}
        while True:
            model_started = time.monotonic()
            try:
                self._run_model_if_granted(manifest, child_env)
            except Forbidden:
                self.ledger.update(key, status="blocked", repairs=repairs)
                raise
            except TimedOut as error:
                # A model-stage timeout is an environment outcome, not a
                # code failure: no repair attempt, claim stops with the
                # partial output recorded (same semantics as FCC #20).
                logs.append(
                    {
                        "stage": "model",
                        "exit_code": None,
                        "stdout": getattr(error, "stdout_tail", ""),
                        "stderr": getattr(error, "stderr_tail", ""),
                        "error": "timed_out",
                        "duration_seconds": time.monotonic() - model_started,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            except ModelSessionFailed as error:
                # FCC #30 (step-8 run #13): the session ended abnormally —
                # a provider API error after the edits were on disk. The
                # edits do not make the pass complete; stop with the
                # evidence instead of burning the check stage on a dead
                # session. Consumes no repair attempt.
                logs.append(
                    {
                        "stage": "model",
                        "exit_code": error.returncode,
                        # Provider error evidence lives in the stdout
                        # stream-json, not stderr (run #13) — keep both.
                        "stdout": error.stdout_tail,
                        "stderr": error.stderr_tail,
                        "error": "session_failed",
                        "duration_seconds": time.monotonic() - model_started,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            except OSError:
                logs.append(
                    {
                        "stage": "model",
                        "exit_code": None,
                        "stderr": "",
                        "error": "start_failed",
                        "duration_seconds": time.monotonic() - model_started,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            # EXEC-RETRY-01 repair: clear any failed-test record left over
            # from before this pass, so a record read after the pass can
            # only be this pass's own. If a record survives the clearing,
            # no record from this pass is trusted either. Repair 2: a
            # TRACKED record is never unlinked (deleting it would leak a
            # worker-made deletion into the workspace diff) — it is left
            # in place, and its trust is decided after the pass by
            # whether the pass rewrote it.
            stale_record_removed = False
            record_trusted = False
            tracked_record: bytes | None = None
            if self.allow_failed_test_rerun:
                tracked_record = _tracked_run_record(workspace, command_root, record_relative)
                if tracked_record is None:
                    stale_record_removed = _remove_stale_run_record(command_root)
                    record_trusted = not (command_root / _RUN_RECORD).exists()
            # STALL-DIAG-01: the check stage records its wall duration, a
            # machine stats snapshot taken at its start, and the slowest
            # tests from the check evidence — the split the run #21/#25
            # comparison could not make from the old logs.
            check_started = time.monotonic()
            check_machine = machine_stats.snapshot()
            evidence_before = len(sandbox.evidence)
            try:
                evidence = sandbox.run(
                    NativeCommandApproval(manifest.manifest_id, self.allowed_command, attestation.principal_id),
                    manifest=manifest,
                    head_sha=workspace.head(),
                    env=child_env,
                )
            except Forbidden:
                self.ledger.update(key, status="blocked", repairs=repairs)
                raise
            except TimedOut as error:
                # Same semantics as the setup stage (PR #18): a timeout is an
                # environment outcome, not a code failure — it consumes no
                # repair attempt, and the claim stops with the partial output
                # recorded instead of escaping and stranding the claim active
                # (FCC #20, step-8 run #4).
                timed_out_entry: dict[str, object] = {
                    "stage": "test",
                    "exit_code": None,
                    "stderr": getattr(error, "stderr_tail", ""),
                    "error": "timed_out",
                    "duration_seconds": time.monotonic() - check_started,
                    "machine": check_machine,
                }
                if len(sandbox.evidence) > evidence_before:
                    # The sandbox recorded this call's evidence before the
                    # raise; its slowest-tests parse of the partial output
                    # is the stall's best evidence.
                    timed_out_entry["slowest_tests"] = [
                        list(pair) for pair in sandbox.evidence[-1].slowest_tests
                    ]
                logs.append(timed_out_entry)
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            except OSError:
                logs.append(
                    {
                        "stage": "test",
                        "exit_code": None,
                        "stderr": "",
                        "error": "start_failed",
                        "duration_seconds": time.monotonic() - check_started,
                        "machine": check_machine,
                    }
                )
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
            code = evidence.returncode if evidence.returncode is not None else 1
            logs.append(
                {
                    "stage": "test",
                    "exit_code": code,
                    "stderr": evidence.stderr_tail,
                    "duration_seconds": time.monotonic() - check_started,
                    "machine": check_machine,
                    "slowest_tests": [list(pair) for pair in evidence.slowest_tests],
                }
            )
            if stale_record_removed:
                logs[-1]["stale_record_removed"] = True
            if tracked_record is not None:
                logs[-1]["tracked_record_kept"] = True
            if code == 0:
                break
            if tracked_record is not None:
                # The tracked record was left in place; it counts as
                # this pass's own only if the pass rewrote it. Untouched
                # stale bytes keep the failure on the existing repair
                # path below.
                record_trusted = _record_written_by_pass(command_root, tracked_record)
            # The re-run fires only when all three gates hold: the
            # explicit runtime opt-in authorized it, the record read here
            # was written by this pass (the pre-pass clearing left a clean
            # slate, or a tracked record left in place was rewritten by
            # the pass), and that fresh record names at least one failed
            # test. Every other failure shape — no opt-in, a stale or
            # untrusted record, no record — keeps the existing repair path
            # below, exactly as before the feature.
            failed_tests = (
                _recorded_failed_tests(command_root)
                if self.allow_failed_test_rerun and record_trusted
                else ()
            )
            if failed_tests:
                # EXEC-RETRY-01 (Producer flake policy, 2026-11-11): the
                # first pass completed and failed with recorded test
                # failures, so the failed tests get exactly one re-run
                # inside this check stage (Playwright --last-failed). The
                # re-run goes through the same sandbox, so the configured
                # per-command timeout bounds it independently — the stage's
                # worst case is two bounded invocations, and the re-run
                # covers only the failed subset. Timeouts and start
                # failures keep the check stage's existing stop semantics
                # and are never re-run. A re-run pass replaces the stage
                # result (the run proceeds exactly as a first-pass pass);
                # a re-run failure stops the claim with no repair consumed —
                # a model repair pass cannot fix a flake, so the repair
                # loop below stays reserved for failures that recorded no
                # failed tests. Both attempts land in the stage logs: the
                # "test" entry carries the first pass and its failed-test
                # count, the "test_rerun" entry the re-run's own result, so
                # a flake-pass is distinguishable from a clean pass.
                logs[-1]["failed_tests"] = len(failed_tests)
                rerun_started = time.monotonic()
                rerun_evidence_before = len(sandbox.evidence)
                try:
                    rerun_evidence = sandbox.run(
                        NativeCommandApproval(
                            manifest.manifest_id,
                            failed_rerun_command(self.allowed_command),
                            attestation.principal_id,
                        ),
                        manifest=manifest,
                        head_sha=workspace.head(),
                        env=child_env,
                    )
                except Forbidden:
                    self.ledger.update(key, status="blocked", repairs=repairs)
                    raise
                except TimedOut as error:
                    rerun_timed_out_entry: dict[str, object] = {
                        "stage": "test_rerun",
                        "exit_code": None,
                        "stderr": getattr(error, "stderr_tail", ""),
                        "error": "timed_out",
                        "failed_tests": len(failed_tests),
                        "duration_seconds": time.monotonic() - rerun_started,
                    }
                    if len(sandbox.evidence) > rerun_evidence_before:
                        rerun_timed_out_entry["slowest_tests"] = [
                            list(pair) for pair in sandbox.evidence[-1].slowest_tests
                        ]
                    logs.append(rerun_timed_out_entry)
                    self.ledger.update(key, status="stopped", repairs=repairs)
                    return {
                        "status": "stopped",
                        "repair_attempts": repairs,
                        "logs": logs,
                        "head_sha": workspace.head(),
                        "merged": False,
                    }
                except OSError:
                    logs.append(
                        {
                            "stage": "test_rerun",
                            "exit_code": None,
                            "stderr": "",
                            "error": "start_failed",
                            "failed_tests": len(failed_tests),
                            "duration_seconds": time.monotonic() - rerun_started,
                        }
                    )
                    self.ledger.update(key, status="stopped", repairs=repairs)
                    return {
                        "status": "stopped",
                        "repair_attempts": repairs,
                        "logs": logs,
                        "head_sha": workspace.head(),
                        "merged": False,
                    }
                rerun_code = rerun_evidence.returncode if rerun_evidence.returncode is not None else 1
                logs.append(
                    {
                        "stage": "test_rerun",
                        "exit_code": rerun_code,
                        "stderr": rerun_evidence.stderr_tail,
                        "failed_tests": len(failed_tests),
                        "duration_seconds": time.monotonic() - rerun_started,
                        "slowest_tests": [
                            list(pair) for pair in rerun_evidence.slowest_tests
                        ],
                    }
                )
                if rerun_code == 0:
                    evidence = rerun_evidence
                    break
                self.ledger.update(key, status="stopped", repairs=repairs)
                return {
                    "status": "stopped",
                    "repair_attempts": repairs,
                    "logs": logs,
                    "head_sha": workspace.head(),
                    "merged": False,
                }
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
        from free_claude_code.assignments.paths import path_allowed

        changed = tuple(
            path for path in workspace.changed_paths() if path_allowed(path, manifest.scope.allowed_prefixes)
        )
        if changed:
            workspace.commit_scoped(changed, "assignment candidate edit")
        head = workspace.head()
        if head != workspace.head() or not workspace.ancestry_contains(base_sha, head):
            raise Forbidden("resolved HEAD is not based on the approved SHA")
        if workspace.branch_name() != self.identity.feature_branch(attestation.task_id):
            raise Forbidden("HEAD is not the feature branch")
        if not self.publish_enabled:
            raise Disabled("publisher is disabled")
        url = self._publish_subprocess(attestation, head, manifest.manifest_id, number)
        checks = self.api.fetch_check_runs(self.owner, self.repo, head, timeout=self.api.timeout)
        ci = "not_read"
        if checks:
            failed = [item for item in checks if item.get("conclusion") not in {None, "success", "skipped"}]
            ci = "failure" if failed else "success"
        verdict = "HOLD" if ci == "failure" else "PASS"
        status = "ci_hold" if ci == "failure" else "returned_for_review"
        slack = self._post_handoff(number, url, head, attestation, verdict)
        self.ledger.update(
            key,
            status="stopped" if ci == "failure" else "completed",
            repairs=repairs,
            head_sha=head,
            signed_by=attestation.principal_id,
        )
        return {
            "status": status,
            "repair_attempts": repairs,
            "head_sha": head,
            "pr_url": url,
            "branch": workspace.branch_name(),
            "ci": ci,
            "logs": logs,
            "merged": False,
            "child_has_publish_token": False,
            "manager": attestation.principal_id,
            "signed_by": attestation.principal_id,
            "signed_by_name": self.verifier.display_name(attestation.principal_id),
            "slack": slack,
        }

    def _model_now(self) -> int:
        # A frozen zero (the construction default) means "use the real
        # clock": a live candidate must never verify a grant against a
        # stopped clock, or grant expiry never bites. Tests inject `now`
        # (a fixed reading) or replace `clock` to advance time.
        return self.now if self.now else int(self.clock())

    def _run_model_if_granted(self, manifest: object, child_env: dict[str, str]) -> None:
        if self.model_grant is None and self.model_grant_factory is not None:
            self.model_grant = self.model_grant_factory(manifest)
        if self.model_grant is None and self.grants_dir is not None:
            self.model_grant = load_grant(
                self.grants_dir / f"{manifest.manifest_id}.json"  # type: ignore[attr-defined]
            )
        if self.model_grant is None:
            return
        if not self.grant_key:
            raise Forbidden("a model grant is present but no grant key is configured")
        from free_claude_code.assignments.execution import NvidiaClaudeLauncher

        # The launcher plants this snapshot as the task card and checks its
        # revision against the signed manifest before the model launches.
        issue = self.api.fetch_issue(
            manifest.owner,  # type: ignore[attr-defined]
            manifest.repo,  # type: ignore[attr-defined]
            manifest.issue_number,  # type: ignore[attr-defined]
            timeout=self.api.timeout,
        )
        proxy_auth = load_secret_file(self.paths.secrets_file).get("proxy_auth")
        launcher = NvidiaClaudeLauncher("claude", self.model_proxy_base_url, proxy_auth)
        if self.model_spawn is None:
            launcher.run(
                manifest,  # type: ignore[arg-type]
                self.paths.workspace,
                self.model_grant,
                issue=issue,
                grant_key=self.grant_key,
                now=self._model_now(),
                revocations=load_revocations(self.paths.state_dir / "revocations.txt"),
                spawn=None,
            )
            return

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
            issue=issue,
            grant_key=self.grant_key,
            now=self._model_now(),
            revocations=load_revocations(self.paths.state_dir / "revocations.txt"),
            spawn=spawn,
        )
        if any(name in child_env for name in PUBLISHER_ENV):
            raise Forbidden("publisher credential reached a child environment")

    def _deliver_slack(self, line: str) -> None:
        """Post the handoff when this worker's poster is enabled. Failure keeps the line."""

        if not self.identity.slack_enabled:
            return
        config_path = self.paths.state_dir / "slack-config.json"
        state_dir = self.paths.state_dir / "slack"
        _atomic_json(
            config_path,
            {
                "api_base": self.slack_api_base,
                "channel_id": self.identity.slack_channel_id,
                "enabled": True,
                "secrets_file": str(self.paths.secrets_file),
                "state_dir": str(state_dir),
                "text": line,
            },
        )
        try:
            subprocess.run(
                [sys.executable, "-m", "free_claude_code.assignments.slack_poster", "--config", str(config_path)],
                cwd=str(Path(self.paths.state_dir).expanduser().resolve(strict=False)),
                env=_child_env(),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return

    def _publisher_login(self) -> str:
        token = load_secret_file(self.paths.secrets_file).get("github_publish")
        client = GitHubHttpClient(self.api.base_url, token, timeout=self.api.timeout)
        return client.fetch_authenticated_login(timeout=self.api.timeout)

    def _route_sha(self, number: int, base_sha: str) -> str:
        """PR handoffs bind to the pull head. Issue tasks keep the base SHA."""

        try:
            pull = self.api.fetch_pull(self.owner, self.repo, number, timeout=self.api.timeout)
        except Forbidden as exc:
            if "404" in str(exc):
                return base_sha
            raise
        head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
        sha = str(head.get("sha", "")) if isinstance(head, dict) else ""
        return sha or base_sha

    def _inbox_issue_numbers(self) -> tuple[int, ...]:
        inbox = self.paths.inbox
        if not inbox.is_dir():
            return ()
        numbers: list[int] = []
        for path in sorted(inbox.glob("*.json")):
            if path.stem.isdigit():
                numbers.append(int(path.stem))
        return tuple(numbers)

    def _route(self, number: int, labels: tuple[str, ...], live_sha: str) -> str:
        if self.waiting_label in labels:
            return "label"
        matched = False
        stale = False
        for comment in self.api.list_issue_comments(self.owner, self.repo, number, timeout=self.api.timeout):
            body = str(comment.get("body", ""))
            if not any(line.strip() == f"NEXT: {self.identity.bare_name}" for line in body.splitlines()):
                continue
            signature = _signature_from_comment(body)
            if signature is None:
                continue
            payload = _comment_payload(body)
            if not any(verify_ed25519(key, payload, signature) for key in self.verifier.public_keys()):
                continue
            head = ""
            for line in body.splitlines():
                if line.startswith("HEAD:"):
                    head = line.split(":", 1)[1].strip()
            if head == live_sha:
                matched = True
            else:
                stale = True
        if matched:
            return "comment"
        if stale:
            return "stale"
        return "absent"

    def _publish_subprocess(self, attestation: ManagerAttestation, head: str, manifest_id: str, number: int) -> str:
        config_path = self.paths.state_dir / "publish-config.json"
        raw = {
            "enabled": True,
            "secrets_file": str(self.paths.secrets_file),
            "workspace": str(self.paths.workspace),
            "task_id": attestation.task_id.lower(),
            "origin": self.publish_origin,
            "api_base": self.api.base_url,
            "owner": self.owner,
            "repo": self.repo,
            "base_branch": attestation.base_branch,
            "title": f"Review assignment #{number}",
            "body": f"Resolved head: {head}\n",
            "head_sha": head,
            "author_id": self.identity.actor_name,
            "branch_prefix": self.identity.branch_prefix,
            "comment_signature": self.identity.comment_signature,
            "reviewer_id": attestation.principal_id,
            "manifest_id": manifest_id,
        }
        if self.publish_ca_file:
            raw["ca_file"] = str(self.publish_ca_file)
        _atomic_json(config_path, raw)
        completed = subprocess.run(
            [sys.executable, "-m", "free_claude_code.assignments.publisher", "--config", str(config_path)],
            cwd=str(Path(self.paths.state_dir).expanduser().resolve(strict=False)),
            env=_child_env(),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = (completed.stdout + completed.stderr)[-400:]
            raise Forbidden(f"publisher process failed: {detail}")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise Forbidden("publisher process failed") from exc
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            raise Forbidden("publisher process failed")
        return url

    def _post_handoff(
        self, number: int, url: str, head: str, attestation: ManagerAttestation, verdict: str
    ) -> str:
        name = self.verifier.display_name(attestation.principal_id)
        interim = self.verifier.interim_until(attestation.principal_id)
        interim_line = f"INTERIM UNTIL: {interim}\n" if interim else ""
        actor, label = self.verifier.handoff_for(attestation.principal_id)
        self.api.replace_waiting_label(
            self.owner,
            self.repo,
            number,
            remove=self.waiting_label,
            add=label,
            timeout=self.api.timeout,
        )
        handoff = (
            f"PR: {url}\nHEAD: {head}\n"
            f"SIGNED BY: {attestation.principal_id} ({name})\n"
            f"{interim_line}"
            f"NEXT: {actor}\n"
            "ACTION: independent review\nLIMITATIONS: local runners only\n"
            f"{self.identity.comment_suffix()}"
        )
        self.api.post_issue_comment(self.owner, self.repo, number, handoff, timeout=self.api.timeout)
        task_id = attestation.task_id.lower()
        line = f"HANDOFF: {task_id} | {url} | {head} | {verdict} | NEXT: {actor}"
        self._deliver_slack(line)
        return line

    def review_pull(self, number: int) -> dict[str, object]:
        """Read-only review. A PASS is a signed comment, never a merge approval."""

        if not self.enabled:
            raise Disabled("assignment candidate is disabled")
        pull = self.api.fetch_pull(self.owner, self.repo, number, timeout=self.api.timeout)
        author = _login(pull.get("user"))
        head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
        live = str(head.get("sha", "")) if isinstance(head, dict) else ""
        pusher = _login(head.get("user")) if isinstance(head, dict) else ""
        logins = set(self.identity.own_logins())
        logins.add(self._publisher_login())
        assert_independent_reviewer(
            author_login=author, pusher_login=pusher, logins=frozenset(logins)
        )
        assert_reviewer_is_not_author(author_login=author, reviewer_login=self.identity.bare_name)
        if not live:
            raise Forbidden("pull request has no head")
        checkout = self.paths.state_dir / "review-checkout"
        if checkout.exists():
            raise Forbidden("review checkout already exists")
        workspace = GitWorkspace(checkout)
        landed = workspace.materialize_detached(self.paths.source_repo, live)
        if landed != live:
            raise Forbidden("review checkout is not the pull head")
        again = self.api.fetch_pull(self.owner, self.repo, number, timeout=self.api.timeout)
        again_head = again.get("head") if isinstance(again.get("head"), dict) else {}
        current = str(again_head.get("sha", "")) if isinstance(again_head, dict) else ""
        verdict = "STALE" if current != live else "PASS"
        findings = "head moved before the verdict was posted" if verdict == "STALE" else "local checks passed"
        if verdict == "PASS":
            manifest = _review_manifest(live)
            sandbox = Sandbox(checkout / self.command_cwd, allowed=(self.allowed_command,), timeout_seconds=self.command_timeout_seconds)
            evidence = sandbox.run(
                NativeCommandApproval(manifest.manifest_id, self.allowed_command, self.identity.actor_name),
                manifest=manifest,
                head_sha=live,
                env=scrub_env(os.environ),
            )
            if evidence.returncode != 0:
                verdict = "HOLD"
                findings = "local checks failed"
        signature = self._sign_verdict(verdict, live, findings)
        body = (
            f"VERDICT: {verdict}\nHEAD: {live}\nFINDINGS: {findings}\n"
            "LIMITATIONS: local runners only\n"
            f"SIGNATURE: {signature}\n"
            f"{self.identity.comment_suffix()}"
        )
        self.api.post_issue_comment(self.owner, self.repo, number, body, timeout=self.api.timeout)
        return {"status": "stale" if verdict == "STALE" else "reviewed", "verdict": verdict, "head_sha": live, "merged": False}

    def _sign_verdict(self, verdict: str, head_sha: str, findings: str) -> str:
        if self.verdict_key_file is None:
            raise Forbidden("verdict signing key is not configured")
        config_path = self.paths.state_dir / "verdict-config.json"
        _atomic_json(
            config_path,
            {
                "actor": self.identity.actor_name,
                "findings": findings,
                "head_sha": head_sha,
                "limitations": "local runners only",
                "private_key_file": str(self.verdict_key_file),
                "verdict": verdict,
            },
        )
        completed = subprocess.run(
            [sys.executable, "-m", "free_claude_code.assignments.verdict_sign", "--config", str(config_path)],
            cwd=str(Path(self.paths.state_dir).expanduser().resolve(strict=False)),
            env=_child_env(),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = (completed.stdout + completed.stderr)[-400:]
            raise Forbidden(f"verdict signer failed: {detail}")
        payload = json.loads(completed.stdout)
        signature = payload.get("signature")
        if not isinstance(signature, str):
            raise Forbidden("verdict signer failed")
        return signature

    def _service(self, number: int, base_branch: str) -> AssignmentService:
        config = AssignmentConfig(
            enabled=True,
            allowlist=(AllowlistEntry(self.owner, self.repo, number, base_branch),),
            operators=self.verifier.principal_ids,
            # The allowlist entry is synthesized from a signature-verified
            # attestation whose base_sha was checked against the live head
            # of this branch, so the operator-file guard against protected
            # base branches does not apply here.
            forbidden_branches=(),
            allowed_path_prefixes=self.allowed_path_prefixes,
            setup_command=self.setup_command or (),
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
            task_id=str(raw["task_id"]),
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
    write_private_bytes(target / "enabled", b"false\n")
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


def _platform_name() -> str:
    return os.name


def _child_env() -> dict[str, str]:
    """Environment for a helper process. Secrets stay out. The package path is absolute."""

    env = scrub_env(os.environ)
    src = Path(__file__).resolve().parents[2]
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(src) if not current else str(src) + os.pathsep + current
    env.pop("FCC_PUBLISH_TOKEN", None)
    env.pop("FCC_ASKPASS_FILE", None)
    return env


def _private_dir(path: Path) -> Path:
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    path.mkdir(parents=True, exist_ok=True)
    if _platform_name() == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only, harden_path

        harden_path(path)
        if not file_is_current_user_only(path):
            raise Forbidden("state directory is not owned by the current user")
        return path
    os.chmod(path, 0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise Forbidden("state directory is not private")
    return path


def _interim_expired(until: str, now: int) -> bool:
    """True after the UTC calendar day named by YYYY-MM-DD. That day is still valid."""

    if not until:
        return False
    try:
        year, month, day = (int(part) for part in until.split("-"))
        deadline = datetime(year, month, day, tzinfo=timezone.utc) + timedelta(days=1)
    except ValueError as exc:
        raise ApprovalInvalid("interim_until is not a calendar date") from exc
    return datetime.fromtimestamp(now, tz=timezone.utc) >= deadline


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if _platform_name() == "nt":
        from free_claude_code.assignments.windows_acl import windows_pid_alive

        return windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _io_flags(*parts: int) -> int:
    """Binary create flags. Windows text mode rewrites 0x0A and breaks the MAC key."""

    flags = 0
    for part in parts:
        flags |= part
    if os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    binary = getattr(os, "O_BINARY", 0)
    return flags | binary


def _atomic_json(path: Path, payload: object) -> None:
    atomic_write_private(path, (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def _read_lines(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _write_lines(path: Path, values: set[str]) -> None:
    atomic_write_private(path, ("".join(f"{item}\n" for item in sorted(values))).encode("utf-8"))


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
