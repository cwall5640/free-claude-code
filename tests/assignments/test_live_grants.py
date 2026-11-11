import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.errors import ApprovalInvalid, Forbidden
from free_claude_code.assignments.grants import ModelGrant, load_grant, sign_grant
from free_claude_code.assignments.models import Scope, TaskManifest
from free_claude_code.assignments.secrets import SecretFile, write_secret_file
from free_claude_code.assignments.workflow import AssignmentCandidate, CandidatePaths

GRANT_KEY = "grant-key"


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


def _signed(manifest: TaskManifest, *, key: str = GRANT_KEY, expires_at: int = 5_000) -> ModelGrant:
    return sign_grant(
        key,
        ModelGrant(
            manifest_id=manifest.manifest_id,
            repo=f"{manifest.owner}/{manifest.repo}",
            base_sha=manifest.base_sha,
            issue_revision=manifest.issue_revision,
            expires_at=expires_at,
            actions=("implement",),
            signature="",
        ),
    )


def _manifest() -> TaskManifest:
    return TaskManifest(
        task_key="cwall5640/fixture#9",
        owner="cwall5640",
        repo="fixture",
        issue_number=9,
        issue_revision="r" * 64,
        title_redacted="test task",
        base_branch="dev",
        base_sha="a" * 40,
        scope=Scope(("src",), 1000),
    )


# ---------- load_grant ----------

def test_load_grant_round_trip(tmp_path):
    manifest = _manifest()
    grant = _signed(manifest)
    path = tmp_path / f"{manifest.manifest_id}.json"
    path.write_text(json.dumps(_grant_dict(grant)), encoding="utf-8")
    loaded = load_grant(path)
    assert loaded == grant


def test_load_grant_missing_file_is_none(tmp_path):
    assert load_grant(tmp_path / "absent.json") is None


def test_load_grant_malformed_fails_loudly(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ApprovalInvalid):
        load_grant(path)
    path.write_text(json.dumps({"manifest_id": "x"}), encoding="utf-8")
    with pytest.raises(ApprovalInvalid):
        load_grant(path)


# ---------- live seam: _candidate wires the grant ----------

def _runtime(tmp_path: Path) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    return {
        "managers_file": "managers.json",
        "secrets_file": "secrets",
        "source_repo": str(source),
        "audience": "worker",
        "owner": "owner",
        "repo": "game",
        "github_api_base": "https://api.github.test",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "allowed_command": ("python", "check.py"),
        "command_cwd": "src",
        "allowed_path_prefixes": ("src",),
        "command_timeout_seconds": 10.0,
        "setup_command": None,
        "publish_origin": "",
        "ca_file": "",
    }


def test_candidate_wires_grant_key_and_grants_dir(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: SecretFile({"github_read": "t", "grant_key": "gk-123"}))
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", capture)
    state = tmp_path / "state"
    candidate = live._candidate(state, tmp_path, _runtime(tmp_path))
    assert captured["grants_dir"] == state / "grants"
    assert candidate.grant_key == "gk-123"


def test_candidate_without_grant_key_stays_ungranted(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: SecretFile({"github_read": "t"}))
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", lambda **kwargs: SimpleNamespace(**kwargs))
    candidate = live._candidate(tmp_path / "state", tmp_path, _runtime(tmp_path))
    assert candidate.grant_key == ""


# ---------- workflow behavior: grant file drives the model pass ----------

class _IssueStub:
    """Snapshot stand-in for the granted path: the launcher reads the
    revision (to check it against the manifest) plus title/body for the
    planted task card. The synthetic manifest's revision is "r" * 64."""

    title = "test task"
    body = "test task body"

    def revision(self) -> str:
        return "r" * 64


class _ApiStub:
    timeout = 5.0

    def fetch_issue(self, owner: str, repo: str, number: int, *, timeout: float) -> _IssueStub:
        return _IssueStub()


def _candidate(tmp_path: Path, grants_dir: Path, *, now: int = 1_000) -> AssignmentCandidate:
    state = tmp_path / "state"
    secrets = tmp_path / "secrets" / "values"
    write_secret_file(secrets, {"proxy_auth": "proxy-token", "grant_key": GRANT_KEY})
    (tmp_path / "workspace").mkdir(exist_ok=True)
    candidate = AssignmentCandidate(
        enabled=True,
        owner="cwall5640",
        repo="fixture",
        api=_ApiStub(),
        paths=CandidatePaths(
            state_dir=state,
            source_repo=tmp_path,
            workspace=tmp_path / "workspace",
            secrets_file=secrets,
            inbox=state / "inbox",
            power_file=state / "power",
            session_file=state / "session",
            network_file=state / "network",
            local_remote=tmp_path / "bare.git",
        ),
        verifier=object(),
        operator_id="operator",
        reviewer_id="reviewer",
        allowed_command=("python", "check.py"),
        command_cwd="src",
        grants_dir=grants_dir,
    )
    candidate.grant_key = GRANT_KEY
    candidate.now = now
    candidate._publish_token = "publish-token-fixture"
    return candidate


def test_model_pass_runs_from_grant_file(tmp_path):
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / f"{manifest.manifest_id}.json").write_text(
        json.dumps(_grant_dict(_signed(manifest))), encoding="utf-8"
    )
    candidate = _candidate(tmp_path, grants_dir)
    seen: dict[str, object] = {}
    candidate.model_spawn = lambda argv, env, workspace: seen.update(argv=argv, workspace=workspace)
    candidate._run_model_if_granted(manifest, {})
    assert seen["argv"], "model pass should have spawned the launcher"
    assert seen["workspace"] == tmp_path / "workspace"


def test_model_pass_skips_without_grant_file(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    candidate = _candidate(tmp_path, grants_dir)
    seen: dict[str, object] = {}
    candidate.model_spawn = lambda argv, env, workspace: seen.update(argv=argv)
    candidate._run_model_if_granted(_manifest(), {})
    assert not seen


def test_model_pass_rejects_revoked_grant(tmp_path):
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / f"{manifest.manifest_id}.json").write_text(
        json.dumps(_grant_dict(_signed(manifest))), encoding="utf-8"
    )
    candidate = _candidate(tmp_path, grants_dir)
    candidate.model_spawn = lambda argv, env, workspace: None
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "state" / "revocations.txt").write_text(manifest.manifest_id + "\n", encoding="utf-8")
    with pytest.raises(ApprovalInvalid):
        candidate._run_model_if_granted(manifest, {})


def test_model_pass_rejects_wrong_key_grant(tmp_path):
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / f"{manifest.manifest_id}.json").write_text(
        json.dumps(_grant_dict(_signed(manifest, key="some-other-key"))), encoding="utf-8"
    )
    candidate = _candidate(tmp_path, grants_dir)
    candidate.model_spawn = lambda argv, env, workspace: None
    with pytest.raises(ApprovalInvalid):
        candidate._run_model_if_granted(manifest, {})


def _write_grant(grants_dir: Path, grant: ModelGrant) -> None:
    grants_dir.mkdir(exist_ok=True)
    (grants_dir / f"{grant.manifest_id}.json").write_text(
        json.dumps(_grant_dict(grant)), encoding="utf-8"
    )


def test_model_pass_rejects_expired_grant_on_the_real_clock(tmp_path):
    # now=0 is the live construction default: the candidate must read the
    # real clock, so a grant that expired in 1970 is rejected even though
    # no test clock was injected.
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    _write_grant(grants_dir, _signed(manifest, expires_at=1))
    candidate = _candidate(tmp_path, grants_dir, now=0)
    candidate.model_spawn = lambda argv, env, workspace: pytest.fail("must not spawn")
    with pytest.raises(ApprovalInvalid):
        candidate._run_model_if_granted(manifest, {})


def test_model_pass_advancing_clock_rejects_after_expiry(tmp_path):
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    _write_grant(grants_dir, _signed(manifest, expires_at=5_000))
    candidate = _candidate(tmp_path, grants_dir, now=1_000)
    spawns: list[object] = []
    candidate.model_spawn = lambda argv, env, workspace: spawns.append(argv)
    candidate._run_model_if_granted(manifest, {})
    assert len(spawns) == 1
    candidate.now = 6_000
    with pytest.raises(ApprovalInvalid):
        candidate._run_model_if_granted(manifest, {})
    assert len(spawns) == 1, "an expired grant must not spawn a repair pass"


def test_model_pass_fails_closed_without_a_grant_key(tmp_path):
    manifest = _manifest()
    grants_dir = tmp_path / "grants"
    # A grant signed with the publicly known empty key must never verify:
    # with no key configured the candidate refuses before the launcher.
    _write_grant(grants_dir, _signed(manifest, key=""))
    candidate = _candidate(tmp_path, grants_dir)
    candidate.grant_key = ""
    candidate.model_spawn = lambda argv, env, workspace: pytest.fail("must not spawn")
    with pytest.raises(Forbidden, match="no grant key is configured"):
        candidate._run_model_if_granted(manifest, {})
