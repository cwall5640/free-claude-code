# SPDX-License-Identifier: AGPL-3.0-only
"""Mocked automatic assignment workflow. No network, model, or live GitHub calls."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from free_claude_code.assignments.cli import main as cli_main
from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    Conflict,
    Disabled,
    Forbidden,
    MergeRejected,
)
from free_claude_code.assignments.paths import safe_relative
from free_claude_code.assignments.workflow import (
    CAPABILITY_BOUNDARY,
    ROUTING_LABEL,
    AssignmentWorkflow,
    ClaimLedger,
    GitHubTaskRecord,
    MachineGate,
    ManagerAttestation,
    ProducerDecision,
    RepoAccess,
    RunnerView,
    SeparatePublisher,
    StageResult,
    WorkflowPolicy,
    admit_machine,
    assert_private_file,
    evidence_directory,
    record_stage,
    refuse_reparse,
    sign_attestation,
    sign_producer_decision,
    start_from_label,
)

MANAGER_KEY = "manager-key"
PRODUCER_KEY = "producer-key"
TOKEN = "ghp_" + ("c" * 36)


def _policy(**overrides: object) -> WorkflowPolicy:
    raw: dict[str, object] = {
        "worker_principal_id": "worker-1",
        "producer_principal_id": "casey",
        "producer_key": PRODUCER_KEY,
        "manager_keys": {"vibe-1": MANAGER_KEY, "pm-1": MANAGER_KEY},
    }
    raw.update(overrides)
    return WorkflowPolicy(**raw)  # type: ignore[arg-type]


def _record(**overrides: object) -> GitHubTaskRecord:
    raw: dict[str, object] = {
        "owner": "cwall5640",
        "repo": "fixture",
        "number": 9,
        "node_id": "NODE9",
        "state": "open",
        "updated_at": "2026-11-08T19:45:00Z",
        "base_branch": "dev",
        "base_sha": "abc123def456",
        "labels": (ROUTING_LABEL,),
        "author_login": "VibeCoder",
        "author_id": "display-only",
    }
    raw.update(overrides)
    return GitHubTaskRecord(**raw)  # type: ignore[arg-type]


def _attestation(record: GitHubTaskRecord, principal: str = "vibe-1", **overrides: object) -> ManagerAttestation:
    raw: dict[str, object] = {
        "principal_id": principal,
        "role": "vibe",
        "owner": record.owner,
        "repo": record.repo,
        "issue_number": record.number,
        "issue_node_id": record.node_id,
        "base_sha": record.base_sha,
        "updated_at": record.updated_at,
        "decision": "assign",
        "signature": "",
    }
    raw.update(overrides)
    unsigned = ManagerAttestation(**raw)  # type: ignore[arg-type]
    key = str(_policy().manager_keys.get(str(raw["principal_id"]), MANAGER_KEY))
    return sign_attestation(key, unsigned)


def _awake() -> MachineGate:
    return MachineGate(signed_in=True, active=True, plugged_in=True, online=True)


def _access() -> RepoAccess:
    return RepoAccess(pull=True, push=True)


def _pass(stage: str = "test", head: str = "head999") -> StageResult:
    return StageResult(stage, 0, stderr="Ran 1 test\nOK\n", kind="pass", head_sha=head)


def _fail(stage: str = "test", code: int = 1) -> StageResult:
    return StageResult(stage, code, stderr="FAILED\n", kind="test_failure")


def _engine(tmp: Path, policy: WorkflowPolicy | None = None) -> AssignmentWorkflow:
    return AssignmentWorkflow(policy or _policy(), ClaimLedger(tmp / "state"))


def test_label_display_name_and_shared_login_are_not_origin(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    with pytest.raises(Forbidden):
        start_from_label(record)
    with pytest.raises(Forbidden):
        engine.evaluate(record, None, machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))
    shared = _policy(worker_principal_id="vibe-1")
    engine = AssignmentWorkflow(shared, engine.ledger)
    forged = _attestation(record, principal="vibe-1")
    with pytest.raises(Forbidden, match="shared principal"):
        engine.evaluate(record, forged, machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))


def test_forged_and_unknown_sender_are_refused(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    bad = _attestation(record)
    bad = ManagerAttestation(
        principal_id=bad.principal_id,
        role=bad.role,
        owner=bad.owner,
        repo=bad.repo,
        issue_number=bad.issue_number,
        issue_node_id=bad.issue_node_id,
        base_sha=bad.base_sha,
        updated_at=bad.updated_at,
        decision=bad.decision,
        signature="0" * 64,
    )
    with pytest.raises(ApprovalInvalid):
        engine.evaluate(record, bad, machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))
    stranger = sign_attestation(MANAGER_KEY, ManagerAttestation(
        "stranger", "vibe", record.owner, record.repo, record.number, record.node_id,
        record.base_sha, record.updated_at, "assign", "",
    ))
    with pytest.raises(Forbidden, match="authorized manager"):
        engine.evaluate(record, stranger, machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))


def test_verified_assignment_publishes_without_merge(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    publisher = SeparatePublisher(TOKEN)
    result = engine.evaluate(
        record,
        _attestation(record, principal="pm-1", role="project_manager"),
        machine=_awake(),
        access=_access(),
        stages=(_pass(),),
        publisher=publisher,
    )
    assert result.status == "returned_for_review"
    assert result.merged is False
    assert result.head_sha == "head999"
    assert result.pr_url.endswith("fcc-task/9-abc123def456")
    assert result.manager_principal_id == "pm-1"
    assert publisher.opened[0]["base"] == "dev"
    with pytest.raises(MergeRejected):
        publisher.merge()
    again = _engine(tmp_path)
    again.ledger = engine.ledger
    with pytest.raises(Conflict):
        again.evaluate(record, _attestation(record), machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))


def test_duplicate_claim_is_idempotent_and_one_job(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    first = engine.ledger.claim(record, "worker-1")
    second = engine.ledger.claim(record, "worker-1")
    assert first == second
    other = _record(number=10, node_id="NODE10")
    with pytest.raises(Conflict, match="already active"):
        engine.ledger.claim(other, "worker-1")


def test_stale_head_and_cancel_do_not_revive(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    engine.ledger.claim(record, "worker-1")
    moved = _record(base_sha="fff999aaa000")
    with pytest.raises(ApprovalInvalid, match="base SHA"):
        engine.evaluate(moved, _attestation(moved), machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))
    with pytest.raises(ApprovalInvalid):
        engine.evaluate(moved, _attestation(moved), machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))
    fresh = AssignmentWorkflow(_policy(), engine.ledger.__class__(tmp_path / "other"))
    cancelled = fresh.evaluate(
        record,
        _attestation(record, decision="cancel"),
        machine=_awake(),
        access=_access(),
        stages=(_pass(),),
        publisher=SeparatePublisher(TOKEN),
    )
    assert cancelled.status == "cancelled"
    assert cancelled.pr_url == ""
    with pytest.raises(Conflict):
        fresh.evaluate(record, _attestation(record), machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))


def test_interrupted_claim_resumes_same_head(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    engine.ledger.claim(record, "worker-1")
    engine.ledger.update(record.key, status="interrupted", repairs=1)
    result = engine.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_pass(),),
        publisher=SeparatePublisher(TOKEN),
    )
    assert result.status == "returned_for_review"
    assert result.repair_attempts == 1


def test_repair_budget_stops_and_denials_do_not_retry(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    publisher = SeparatePublisher(TOKEN)
    stopped = engine.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_fail(), _fail(), _fail()),
        publisher=publisher,
    )
    assert stopped.status == "stopped"
    assert stopped.repair_attempts == 2
    assert stopped.pr_url == ""
    assert [item.exit_code for item in stopped.stages] == [1, 1, 1]
    denied = AssignmentWorkflow(_policy(), engine.ledger.__class__(tmp_path / "deny"))
    denial = StageResult("coding", 2, stderr="permission denied", kind="denial")
    blocked = denied.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(denial, _pass()),
        publisher=SeparatePublisher(TOKEN),
    )
    assert blocked.status == "blocked"
    assert blocked.repair_attempts == 0
    assert len(blocked.stages) == 1


def test_stderr_does_not_override_exit_code_and_secrets_are_redacted() -> None:
    noisy = StageResult("test", 0, stderr="progress .\n" + TOKEN, kind="pass", head_sha="abc")
    recorded = record_stage(noisy)
    assert recorded.passed is True
    assert recorded.exit_code == 0
    assert TOKEN not in recorded.detail
    assert "[redacted]" in recorded.detail
    failed = record_stage(StageResult("test", 1, stderr="Ran 1 test\nOK\n", kind="test_failure"))
    assert failed.passed is False
    assert failed.exit_code == 1


def test_publisher_credentials_do_not_reach_model_env() -> None:
    publisher = SeparatePublisher(TOKEN)
    source = {"PATH": "/usr/bin", "GITHUB_TOKEN": TOKEN, "FCC_PUBLISH_TOKEN": "other", "LANG": "C"}
    cleaned = publisher.model_environment(source)
    assert "GITHUB_TOKEN" not in cleaned
    assert "FCC_PUBLISH_TOKEN" not in cleaned
    assert TOKEN not in cleaned.values()
    assert cleaned["PATH"] == "/usr/bin"


def test_sleep_offline_and_unplugged_queue(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    publisher = SeparatePublisher(TOKEN)
    asleep = engine.evaluate(
        record,
        _attestation(record),
        machine=MachineGate(True, True, False, True),
        access=_access(),
        stages=(_pass(),),
        publisher=publisher,
    )
    assert asleep.status == "queue_sleep"
    assert publisher.opened == []
    assert admit_machine(MachineGate(True, True, True, False)) == "queue_offline"
    offline = engine.evaluate(
        record,
        _attestation(record),
        machine=MachineGate(True, True, True, False),
        access=_access(),
        stages=(_pass(),),
        publisher=publisher,
    )
    assert offline.status == "queue_offline"
    assert engine.ledger.get(record.key) is None


def test_ci_local_only_and_no_paid_or_inkbound(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    hosted = RunnerView("hosted", "cwall5640/fixture", ("ubuntu-latest",), True, False)
    refused = engine.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_pass(stage="ci", head="head999"),),
        publisher=SeparatePublisher(TOKEN),
        runners=(hosted,),
    )
    assert refused.status == "blocked"
    ink = AssignmentWorkflow(_policy(), engine.ledger.__class__(tmp_path / "ink"))
    inkbound = RunnerView("ebay", "cwall5640/fixture", ("self-hosted", "Windows", "X64", "dell"), True, False)
    blocked = ink.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_pass(stage="ci"),),
        publisher=SeparatePublisher(TOKEN),
        runners=(inkbound,),
    )
    assert blocked.status == "blocked"
    local = AssignmentWorkflow(_policy(), engine.ledger.__class__(tmp_path / "local"))
    runner = RunnerView(
        "pilot",
        "cwall5640/fixture",
        ("self-hosted", "Windows", "X64", "fcc-worker-pilot-only"),
        True,
        False,
    )
    opened = SeparatePublisher(TOKEN)
    result = local.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_pass(stage="test"), _pass(stage="ci")),
        publisher=opened,
        runners=(runner,),
    )
    assert result.status == "returned_for_review"
    assert opened.opened


def test_missing_access_and_producer_cannot_override_security(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    record = _record()
    with pytest.raises(Forbidden, match="pull and push"):
        engine.evaluate(
            record,
            _attestation(record),
            machine=_awake(),
            access=RepoAccess(False, False, admin=True),
            stages=(_pass(),),
            publisher=SeparatePublisher(TOKEN),
        )
    policy = _policy(plan_blocked_repos=("cwall5640/fixture",))
    blocked = AssignmentWorkflow(policy, engine.ledger.__class__(tmp_path / "plan"))
    with pytest.raises(Forbidden, match="plan excludes"):
        blocked.evaluate(record, _attestation(record), machine=_awake(), access=_access(), stages=(_pass(),), publisher=SeparatePublisher(TOKEN))
    unsafe = sign_producer_decision(PRODUCER_KEY, ProducerDecision("casey", record.owner, record.repo, "merge", ""))
    with pytest.raises(Forbidden, match="security"):
        blocked.evaluate(
            record,
            _attestation(record),
            machine=_awake(),
            access=_access(),
            stages=(_pass(),),
            publisher=SeparatePublisher(TOKEN),
            producer=unsafe,
        )
    allowed = sign_producer_decision(
        PRODUCER_KEY, ProducerDecision("casey", record.owner, record.repo, "project_in_scope", "")
    )
    result = blocked.evaluate(
        record,
        _attestation(record),
        machine=_awake(),
        access=_access(),
        stages=(_pass(),),
        publisher=SeparatePublisher(TOKEN),
        producer=allowed,
    )
    assert result.status == "returned_for_review"


def test_issue_creation_fails_closed_once(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    with pytest.raises(Forbidden, match="403"):
        engine.create_issue()
    assert engine.issues.attempts == 1


def test_activation_and_startup_stay_disabled(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    with pytest.raises(Disabled):
        engine.controls.install()
    with pytest.raises(Disabled):
        engine.controls.activate()
    assert cli_main(["show-contract"]) == 0
    assert cli_main(["install-startup"]) == 2
    assert cli_main(["activate"]) == 2
    assert CAPABILITY_BOUNDARY["activation"] == "disabled"
    rollback = json.loads(
        Path("packaging/assignment-candidate/activation-rollback.json").read_text(encoding="utf-8")
    )
    assert rollback["executed"] is False


def test_paths_acl_and_symlink(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        safe_relative("../secret")
    evidence_directory(tmp_path, "evidence/task")
    secret = tmp_path / "token"
    secret.write_text("hidden", encoding="utf-8")
    os.chmod(secret, 0o600)
    assert_private_file(secret)
    os.chmod(secret, 0o644)
    with pytest.raises(Forbidden):
        assert_private_file(secret)
    link = tmp_path / "link"
    link.symlink_to(secret)
    with pytest.raises(Forbidden):
        refuse_reparse(link)


def test_lf_git_fixture_is_byte_stable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "widget.py"
    source.write_bytes(b"def add(left, right):\n    return left + right\n")
    assert b"\r" not in source.read_bytes()
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@localhost",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@localhost",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        }
    )
    subprocess.run(("git", "-c", "core.autocrlf=false", "init", "-b", "dev"), cwd=repo, env=env, check=True, capture_output=True)
    subprocess.run(("git", "add", "widget.py"), cwd=repo, env=env, check=True, capture_output=True)
    subprocess.run(("git", "commit", "-m", "lf"), cwd=repo, env=env, check=True, capture_output=True)
    blob = subprocess.check_output(("git", "rev-parse", "HEAD:widget.py"), cwd=repo, env=env, text=True).strip()
    show = subprocess.check_output(("git", "cat-file", "-p", blob), cwd=repo, env=env)
    assert show == source.read_bytes()
    assert b"\r" not in show


def test_windows_candidate_package_is_not_executed() -> None:
    script = Path("packaging/assignment-candidate/windows/Invoke-AssignmentCandidate.ps1")
    text = script.read_text(encoding="utf-8")
    assert "\r" not in text
    assert "ExecutionPolicy" not in text
    assert "python -c" not in text
    assert "exit 2" in text
    assert "exit 0" in text
    assert CAPABILITY_BOUNDARY["native_powershell"] == "not_executed"


@pytest.mark.skip(reason="Windows DACL was not executed; this skip is not a security pass")
def test_windows_dacl_native() -> None:
    raise AssertionError("native DACL must not be reported as a cloud pass")


@pytest.mark.skip(reason="Windows reparse points were not created; this skip is not a security pass")
def test_windows_reparse_native() -> None:
    raise AssertionError("native reparse must not be reported as a cloud pass")
