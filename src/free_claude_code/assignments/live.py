# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded pickup. Live only when worker.json and the activation record agree.

A kill switch file stops the loop. A bad signature, a claim conflict, or a
replayed handoff exits immediately. The publisher still cannot merge.
"""

import json
import time
from pathlib import Path

from free_claude_code.assignments.activation import is_activated
from free_claude_code.assignments.errors import ApprovalInvalid, Conflict, Forbidden, ScopeError
from free_claude_code.assignments.fcc_proxy import ensure_fcc_proxy, launcher_from_worker_file
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.identity import load_worker_identity
from free_claude_code.assignments.managers import load_manager_config
from free_claude_code.assignments.models import validate_prefixes
from free_claude_code.assignments.private_io import append_private_bytes, ensure_private_dir
from free_claude_code.assignments.secrets import load_secret_file
from free_claude_code.assignments.workflow import (
    REPAIR_LIMIT,
    AssignmentCandidate,
    CandidatePaths,
    ManagerVerifier,
)

POLL_INTERVAL_SECONDS = 30.0
POLL_LIMIT = 20
KILL_NAME = "KILL"
_QUIET = frozenset(
    {
        "idle",
        "not_routed",
        "queue_sleep",
        "queue_offline",
        "queue_signed_out",
        "queue_sensor_missing",
    }
)


def switches_live(root: Path, config: Path | None) -> bool:
    if config is None or not config.is_dir() or config.is_symlink():
        return False
    return _worker_enabled(config) and is_activated(root)


def run_bounded(root: Path, config: Path, *, sleep=time.sleep) -> int:
    """One bounded poll. Returns 2 when the switches are off or a gate fails."""

    if not switches_live(root, config):
        return 2
    state = ensure_private_dir(root)
    if _killed(state):
        _log(state, "kill switch")
        return 0
    try:
        runtime = _runtime(config)
        launcher = launcher_from_worker_file(config, config.parent)
        if ensure_fcc_proxy(enabled=True, launcher=launcher) not in {"healthy", "started"}:
            _log(state, "proxy down; skipping task")
            return 0
        candidate = _candidate(state, config, runtime)
        for index in range(int(runtime["poll_limit"])):
            if _killed(state):
                _log(state, "kill switch")
                return 0
            try:
                result = candidate.run_once()
            except (ApprovalInvalid, Forbidden, Conflict) as exc:
                _log(state, f"fail closed {exc.code}")
                return 2
            # KILL is cooperative: active subprocess work is not interrupted.
            if _killed(state):
                _log(state, "kill switch after active task")
                return 0
            if result.get("merged") is True:
                _log(state, "merge refused")
                return 2
            if result.get("status") not in _QUIET:
                return 0
            if index + 1 < int(runtime["poll_limit"]) and float(runtime["poll_interval_seconds"]) > 0:
                sleep(float(runtime["poll_interval_seconds"]))
    except (ApprovalInvalid, Forbidden, Conflict) as exc:
        _log(state, f"fail closed {exc.code}")
        return 2
    return 0


def _worker_enabled(config: Path) -> bool:
    worker = config / "worker.json"
    if not worker.is_file() or worker.is_symlink():
        return False
    try:
        raw = json.loads(worker.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError):
        return False
    if not isinstance(raw, dict):
        return False
    flag = raw.get("enabled", False)
    if not isinstance(flag, bool):
        raise Forbidden("enabled must be a boolean")
    return flag


def _runtime(config: Path) -> dict[str, object]:
    path = config / "runtime.json"
    if not path.is_file() or path.is_symlink():
        raise Forbidden("runtime config is missing")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError) as exc:
        raise Forbidden("runtime config is unreadable or malformed") from exc
    if not isinstance(raw, dict):
        raise Forbidden("runtime config is not an object")
    command = raw.get("allowed_command")
    if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
        raise Forbidden("runtime allowed command is missing")
    owner = str(raw.get("owner", "")).strip()
    repo = str(raw.get("repo", "")).strip()
    if not owner or not repo or owner == repo:
        raise Forbidden("runtime repository is missing")
    operator = str(raw.get("operator_id", "")).strip()
    prefixes = raw.get("allowed_path_prefixes", ["src"])
    if not isinstance(prefixes, list) or not prefixes or not all(isinstance(prefix, str) for prefix in prefixes):
        raise Forbidden("runtime allowed path prefixes must be a nonempty list of strings")
    try:
        allowed_path_prefixes = validate_prefixes(tuple(prefixes))
    except ScopeError as exc:
        raise Forbidden("runtime allowed path prefixes are unsafe") from exc
    reviewer = str(raw.get("reviewer_id", "")).strip()
    if not operator or not reviewer or operator == reviewer:
        raise Forbidden("publication needs an independent reviewer")
    interval = raw.get("poll_interval_seconds", POLL_INTERVAL_SECONDS)
    limit = raw.get("poll_limit", POLL_LIMIT)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > POLL_LIMIT:
        raise Forbidden("poll limit is out of bounds")
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval < 0 or interval > 300:
        raise Forbidden("poll interval is out of bounds")
    return {
        "allowed_command": tuple(command),
        "allowed_path_prefixes": allowed_path_prefixes,
        "audience": str(raw.get("audience", "")).strip(),
        "ca_file": str(raw.get("ca_file", "")).strip(),
        "command_cwd": str(raw.get("command_cwd", "src")).strip() or "src",
        "github_api_base": str(raw.get("github_api_base", "")).strip(),
        "managers_file": str(raw.get("managers_file", "managers.json")).strip(),
        "operator_id": operator,
        "owner": owner,
        "poll_interval_seconds": float(interval),
        "poll_limit": limit,
        "publish_origin": str(raw.get("publish_origin", "")).strip(),
        "repo": repo,
        "reviewer_id": reviewer,
        "secrets_file": str(raw.get("secrets_file", "secrets")).strip(),
        "source_repo": str(raw.get("source_repo", "")).strip(),
    }


def _candidate(state: Path, config: Path, runtime: dict[str, object]) -> AssignmentCandidate:
    identity = load_worker_identity(config / "worker.json")
    if not identity.enabled:
        raise Forbidden("worker identity is not enabled")
    managers_path = Path(str(runtime["managers_file"]))
    if not managers_path.is_absolute():
        managers_path = config / managers_path
    managers = load_manager_config(managers_path)
    if not managers:
        raise Forbidden("manager config authorizes nobody")
    secrets_path = Path(str(runtime["secrets_file"]))
    if not secrets_path.is_absolute():
        secrets_path = config / secrets_path
    secrets = load_secret_file(secrets_path)
    source = Path(str(runtime["source_repo"]))
    if not source.is_dir():
        raise Forbidden("source repository is missing")
    audience = str(runtime["audience"])
    if not audience or audience in {item.principal_id for item in managers}:
        raise Forbidden("audience must name the worker and not the manager")
    api = GitHubHttpClient(str(runtime["github_api_base"]), secrets.get("github_read"), timeout=10)
    candidate = AssignmentCandidate(
        enabled=True,
        owner=str(runtime["owner"]),
        repo=str(runtime["repo"]),
        api=api,
        paths=CandidatePaths(
            state_dir=state,
            source_repo=source,
            workspace=state.parent / "workspace",
            secrets_file=secrets_path,
            inbox=state / "inbox",
            power_file=state / "power",
            session_file=state / "session",
            network_file=state / "network",
            local_remote=state.parent / "bare.git",
        ),
        verifier=_verifier(managers, audience, state),
        operator_id=str(runtime["operator_id"]),
        reviewer_id=str(runtime["reviewer_id"]),
        allowed_command=tuple(runtime["allowed_command"]),
        command_cwd=str(runtime["command_cwd"]),
        allowed_path_prefixes=tuple(runtime["allowed_path_prefixes"]),
        repair_limit=REPAIR_LIMIT,
        identity=identity,
    )
    origin = str(runtime["publish_origin"])
    if origin:
        candidate.publish_enabled = True
        candidate.publish_origin = origin
    if runtime["ca_file"]:
        candidate.publish_ca_file = Path(str(runtime["ca_file"]))
    return candidate


def _verifier(managers, audience: str, state: Path) -> ManagerVerifier:
    return ManagerVerifier(
        {item.principal_id: item.public_key for item in managers},
        roles={item.principal_id: item.role for item in managers},
        display_names={item.principal_id: item.display_name for item in managers},
        audience=audience,
        now=int(time.time()),
        state_dir=state / "verifier",
        interim_until={item.principal_id: item.interim_until for item in managers if item.interim_until},
        handoff_actors={item.principal_id: item.handoff_actor for item in managers},
        github_logins={item.principal_id: item.github_login for item in managers},
    )


def _killed(state: Path) -> bool:
    path = state / KILL_NAME
    return path.is_file() and not path.is_symlink()


def _log(state: Path, detail: str) -> None:
    append_private_bytes(state / "logon.log", f"disabled {detail}\n".encode("utf-8"))
