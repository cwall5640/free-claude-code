# SPDX-License-Identifier: AGPL-3.0-only
"""Manager-driven assignment commands. There is no listener and no autostart.

Nothing in this module merges, enables workflows, or reads a secret onto a
command line. Run it only after a later, explicit setup approval.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import AssignmentError
from free_claude_code.assignments.execution import (
    GitWorkspace,
    NativeCommandApproval,
    NvidiaClaudeLauncher,
    Sandbox,
)
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.grants import (
    ModelGrant,
    load_revocations,
    revoke_grant,
    sign_grant,
    verify_grant,
)
from free_claude_code.assignments.models import (
    AllowlistEntry,
    AssignmentConfig,
    TaskManifest,
)
from free_claude_code.assignments.redact import redact
from free_claude_code.assignments.secrets import SecretFile, load_secret_file
from free_claude_code.assignments.service import AssignmentService
from free_claude_code.assignments.store import StateStore


@dataclass(frozen=True, slots=True)
class OperatorFile:
    config: AssignmentConfig
    github_api_base: str
    secrets_file: Path
    state_dir: Path
    proxy_base_url: str
    claude_bin: str
    allowed_commands: tuple[tuple[str, ...], ...]
    source_repo: Path | None


def load_operator_file(path: Path) -> OperatorFile:
    raw = json.loads(path.read_text(encoding="utf-8"))
    allowlist = tuple(
        AllowlistEntry(
            owner=str(item["owner"]),
            repo=str(item["repo"]),
            issue_number=int(item["issue_number"]),
            base_branch=str(item["base_branch"]),
        )
        for item in raw.get("allowlist", [])
    )
    commands = tuple(tuple(str(part) for part in item) for item in raw.get("allowed_commands", []))
    source = raw.get("source_repo")
    return OperatorFile(
        config=AssignmentConfig(
            enabled=bool(raw.get("enabled", False)),
            allowlist=allowlist,
            operators=tuple(str(item) for item in raw.get("operators", [])),
            allowed_path_prefixes=tuple(str(item) for item in raw.get("allowed_path_prefixes", [])),
            fetch_timeout_seconds=float(raw.get("fetch_timeout_seconds", 10)),
        ),
        github_api_base=str(raw["github_api_base"]),
        secrets_file=Path(str(raw["secrets_file"])),
        state_dir=Path(str(raw["state_dir"])),
        proxy_base_url=str(raw.get("proxy_base_url", "http://127.0.0.1:8082")),
        claude_bin=str(raw.get("claude_bin", "claude")),
        allowed_commands=commands,
        source_repo=Path(str(source)) if source else None,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fcc-assignments")
    parser.add_argument("--config")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--owner", required=True)
    fetch.add_argument("--repo", required=True)
    fetch.add_argument("--number", required=True, type=int)
    approve = sub.add_parser("approve")
    approve.add_argument("--phase", required=True)
    approve.add_argument("--operator", required=True)
    sub.add_parser("checkout")
    test = sub.add_parser("test")
    test.add_argument("--command-index", type=int, default=0)
    test.add_argument("--operator", required=True)
    grant = sub.add_parser("grant")
    grant.add_argument("--operator", required=True)
    grant.add_argument("--expires-at", required=True, type=int)
    sub.add_parser("revoke-grant")
    implement = sub.add_parser("implement")
    implement.add_argument("--now", required=True, type=int)
    ci = sub.add_parser("ci-read")
    ci.add_argument("--sha", required=True)
    rerun = sub.add_parser("ci-rerun")
    rerun.add_argument("--job", required=True, type=int)
    publish = sub.add_parser("publish")
    publish.add_argument("--reviewer", required=True)
    sub.add_parser("show-contract")
    install = sub.add_parser("install-startup")
    install.add_argument("--root")
    sub.add_parser("activate")
    args = parser.parse_args(argv)
    if args.command in {"show-contract", "install-startup", "activate"}:
        from free_claude_code.assignments.workflow import candidate_command

        try:
            root = Path(args.root) if getattr(args, "root", None) else None
            return candidate_command(args.command, root)
        except AssignmentError as exc:
            print(json.dumps({"ok": False, "error": exc.code, "detail": redact(str(exc))}))
            return 2
    if not args.config:
        print(json.dumps({"ok": False, "error": "disabled", "detail": "config is required"}))
        return 2
    try:
        operator = load_operator_file(Path(args.config))
        service = AssignmentService(operator.config, StateStore(operator.state_dir))
        secrets = load_secret_file(operator.secrets_file)
        _dispatch(service, operator, secrets, args)
    except AssignmentError as exc:
        print(json.dumps({"ok": False, "error": exc.code, "detail": redact(str(exc))}))
        return 2
    return 0


def _dispatch(service: AssignmentService, operator: OperatorFile, secrets: SecretFile, args: argparse.Namespace) -> None:
    if args.command == "fetch":
        manifest = service.fetch(
            args.owner,
            args.repo,
            args.number,
            reader=_read_client(operator, secrets),
        )
        _save_manifest(operator, manifest)
        _emit({"ok": True, "status": "fetched", "manifest_id": manifest.manifest_id})
        return
    manifest = _load_manifest(operator)
    if args.command == "approve":
        service.approve(
            manifest,
            phase=args.phase,
            operator_id=args.operator,
            reader=_read_client(operator, secrets),
        )
        _emit({"ok": True, "status": f"approved_{args.phase}"})
        return
    if args.command == "checkout":
        if service.store.get_approval(manifest.manifest_id, "execute") is None:
            raise AssignmentError("execute approval is required")
        if operator.source_repo is None or not operator.source_repo.is_dir():
            raise AssignmentError("source_repo must be a local directory")
        if str(operator.source_repo).startswith(("http://", "https://")):
            raise AssignmentError("source_repo must be a local directory")
        service._revalidate(manifest, _read_client(operator, secrets))
        workspace = GitWorkspace(operator.state_dir / "workspace")
        head = workspace.materialize(
            operator.source_repo,
            manifest.base_sha,
            f"fcc-task/{manifest.issue_number}-{manifest.issue_revision[:12]}",
        )
        _emit({"ok": True, "status": "checked_out", "head_sha": head})
        return
    if args.command == "test":
        evidence = _run_indexed_command(service, operator, manifest, args.command_index, args.operator)
        _emit(
            {
                "ok": True,
                "local_tests": evidence.local_outcome,
                "returncode": evidence.returncode,
                "passed": evidence.passed,
                "failed": evidence.failed,
                "skipped": evidence.skipped,
                "head_sha": evidence.head_sha,
                "browser": evidence.browser,
            }
        )
        return
    if args.command == "grant":
        _write_grant(operator, secrets, manifest, args.operator, args.expires_at)
        _emit({"ok": True, "status": "grant_written"})
        return
    if args.command == "revoke-grant":
        revoke_grant(operator.state_dir / "revocations.txt", manifest.manifest_id)
        _emit({"ok": True, "status": "grant_revoked"})
        return
    if args.command == "implement":
        _implement(operator, secrets, manifest, args.now)
        _emit(
            {
                "ok": True,
                "status": "implement_spawned",
                "nvidia_call_verified": False,
            }
        )
        return
    if args.command == "ci-read":
        runs = _ci_client(operator, secrets).fetch_check_runs(
            manifest.owner, manifest.repo, args.sha, timeout=operator.config.fetch_timeout_seconds
        )
        _emit({"ok": True, "checks": len(runs), "action": "read"})
        return
    if args.command == "ci-rerun":
        if service.store.get_approval(manifest.manifest_id, "ci_rerun") is None:
            raise AssignmentError("CI rerun requires its own approval")
        service._revalidate(manifest, _read_client(operator, secrets))
        _ci_client(operator, secrets).rerun_job(
            manifest.owner, manifest.repo, args.job, timeout=operator.config.fetch_timeout_seconds
        )
        _emit({"ok": True, "status": "ci_rerun_requested", "job": args.job})
        return
    if args.command == "publish":
        plan = service.prepare_publication(
            manifest, reader=_read_client(operator, secrets), reviewer_id=args.reviewer
        )
        client = GitHubHttpClient(
            operator.github_api_base,
            secrets.get("github_publish"),
            timeout=operator.config.fetch_timeout_seconds,
        )
        url = client.create_pull_request_for(manifest.owner, manifest.repo, plan)
        _emit({"ok": True, "status": "published", "url": url})
        return
    raise AssignmentError("unknown command")


def _run_indexed_command(service: AssignmentService, operator: OperatorFile, manifest: TaskManifest, index: int, operator_id: str):
    if index < 0 or index >= len(operator.allowed_commands):
        raise AssignmentError("command index is outside the configured allowlist")
    argv = operator.allowed_commands[index]
    workspace = operator.state_dir / "workspace" / "src"
    if not workspace.is_dir():
        workspace = operator.state_dir / "workspace"
    sandbox = Sandbox(workspace, allowed=(argv,))
    head = GitWorkspace(operator.state_dir / "workspace").head()
    return sandbox.run(
        NativeCommandApproval(manifest.manifest_id, argv, operator_id),
        manifest=manifest,
        head_sha=head,
    )


def _write_grant(operator: OperatorFile, secrets: SecretFile, manifest: TaskManifest, operator_id: str, expires_at: int) -> None:
    if operator_id not in operator.config.operators:
        raise AssignmentError("operator is not on the local allowlist")
    if service_execute_missing(operator, manifest):
        raise AssignmentError("execute approval is required before a model grant")
    unsigned = ModelGrant(
        manifest.manifest_id,
        f"{manifest.owner}/{manifest.repo}",
        manifest.base_sha,
        manifest.issue_revision,
        expires_at,
        ("implement",),
        "",
    )
    grant = sign_grant(secrets.get("grant_key"), unsigned)
    path = operator.state_dir / "grants" / f"{manifest.manifest_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_grant_dict(grant), sort_keys=True) + "\n", encoding="utf-8")


def _implement(operator: OperatorFile, secrets: SecretFile, manifest: TaskManifest, now: int) -> None:
    path = operator.state_dir / "grants" / f"{manifest.manifest_id}.json"
    grant = _grant_from_file(path)
    verify_grant(
        secrets.get("grant_key"),
        grant,
        manifest,
        now=now,
        action="implement",
        revocations=load_revocations(operator.state_dir / "revocations.txt"),
    )
    launcher = NvidiaClaudeLauncher(
        operator.claude_bin, operator.proxy_base_url, secrets.get("proxy_auth")
    )
    launcher.run(
        manifest,
        operator.state_dir / "workspace",
        grant,
        grant_key=secrets.get("grant_key"),
        now=now,
        revocations=load_revocations(operator.state_dir / "revocations.txt"),
    )


def service_execute_missing(operator: OperatorFile, manifest: TaskManifest) -> bool:
    store = StateStore(operator.state_dir)
    return store.get_approval(manifest.manifest_id, "execute") is None


def _grant_dict(grant: ModelGrant) -> dict[str, object]:
    return {
        "actions": list(grant.actions),
        "base_sha": grant.base_sha,
        "expires_at": grant.expires_at,
        "issue_revision": grant.issue_revision,
        "manifest_id": grant.manifest_id,
        "repo": grant.repo,
        "signature": grant.signature,
    }


def _grant_from_file(path: Path) -> ModelGrant:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ModelGrant(
        manifest_id=str(raw["manifest_id"]),
        repo=str(raw["repo"]),
        base_sha=str(raw["base_sha"]),
        issue_revision=str(raw["issue_revision"]),
        expires_at=int(raw["expires_at"]),
        actions=tuple(str(item) for item in raw["actions"]),
        signature=str(raw["signature"]),
    )


def _read_client(operator: OperatorFile, secrets: SecretFile) -> GitHubHttpClient:
    return GitHubHttpClient(
        operator.github_api_base,
        secrets.get("github_read"),
        timeout=operator.config.fetch_timeout_seconds,
    )


def _ci_client(operator: OperatorFile, secrets: SecretFile) -> GitHubHttpClient:
    return GitHubHttpClient(
        operator.github_api_base,
        secrets.get("github_ci"),
        timeout=operator.config.fetch_timeout_seconds,
    )


def _save_manifest(operator: OperatorFile, manifest: TaskManifest) -> None:
    from free_claude_code.assignments.service import manifest_payload

    path = operator.state_dir / "current-manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest_payload(manifest, None)
    payload["max_patch_bytes"] = manifest.scope.max_patch_bytes
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _load_manifest(operator: OperatorFile) -> TaskManifest:
    from free_claude_code.assignments.models import ModelProvenance, Scope

    path = operator.state_dir / "current-manifest.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    scope_raw = raw["scope"]
    return TaskManifest(
        task_key=str(raw["task_key"]),
        owner=str(raw["owner"]),
        repo=str(raw["repo"]),
        issue_number=int(raw["issue_number"]),
        issue_revision=str(raw["issue_revision"]),
        title_redacted=str(raw["title_redacted"]),
        base_branch=str(raw["base_branch"]),
        base_sha=str(raw["base_sha"]),
        scope=Scope(tuple(scope_raw["allowed_prefixes"]), int(raw["max_patch_bytes"])),
        model=ModelProvenance(),
    )


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def _entry() -> None:
    sys.exit(main())
