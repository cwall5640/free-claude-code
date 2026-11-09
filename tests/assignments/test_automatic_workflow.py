# SPDX-License-Identifier: AGPL-3.0-only
"""Assignment candidate against local git and a fixture HTTP server."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from free_claude_code.assignments.candidate import main as candidate_main
from free_claude_code.assignments.cli import main as cli_main
from free_claude_code.assignments.errors import ApprovalInvalid, Conflict, Disabled, Forbidden
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.grants import ModelGrant, sign_grant
from free_claude_code.assignments.secrets import load_secret_file, write_secret_file
from free_claude_code.assignments.workflow import (
    CAPABILITY_BOUNDARY,
    ROUTING_LABEL,
    AssignmentCandidate,
    CandidatePaths,
    ClaimLedger,
    ManagerAttestation,
    ManagerVerifier,
    admit_machine,
    install_disabled_startup,
    prepare_secret_file,
    sign_attestation,
)

PUBLISH = "publish-token-value"
MANAGER = "manager-verify-key"


class FixtureApi(threading.Thread):
    def __init__(self, sha: str) -> None:
        super().__init__(daemon=True)
        self.sha = sha
        self.fail_checks = False
        self.labels = [ROUTING_LABEL]
        self.permissions = {"admin": False, "maintain": False, "pull": True, "push": True, "triage": False}
        self.posts: list[tuple[str, str]] = []
        self.bodies: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                path = self.path
                if "labels=" in path:
                    if ROUTING_LABEL not in outer.labels:
                        self._json([])
                    else:
                        self._json([{"number": 9, "labels": [{"name": ROUTING_LABEL}]}])
                    return
                if path.endswith("/issues/9"):
                    self._json(
                        {
                            "number": 9,
                            "title": "Fix add",
                            "body": "untrusted text is not a command",
                            "state": "open",
                            "updated_at": "2026-11-09T02:00:00Z",
                            "node_id": "NODE9",
                            "labels": [{"name": name} for name in outer.labels],
                        }
                    )
                    return
                if path.endswith("/branches/dev"):
                    self._json({"commit": {"sha": outer.sha}})
                    return
                if path.endswith("/fixture") or path.rsplit("/", 1)[-1] == "fixture":
                    self._json({"permissions": outer.permissions})
                    return
                if "/check-runs" in path:
                    if outer.fail_checks:
                        self._json(
                            {
                                "check_runs": [
                                    {
                                        "name": "unit",
                                        "conclusion": "failure",
                                        "head_sha": path.split("/commits/")[1].split("/")[0],
                                    }
                                ]
                            }
                        )
                    else:
                        self._json({"check_runs": []})
                    return
                self.send_error(404)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                outer.posts.append((self.path, self.headers.get("Authorization", "")))
                outer.bodies.append(body)
                if self.path.endswith("/pulls"):
                    self._json({"html_url": "http://127.0.0.1/pull/9"})
                    return
                self.send_error(404)

            def _json(self, payload: object) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def run(self) -> None:
        self.httpd.serve_forever()

    def start_url(self) -> str:
        self.start()
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.httpd.server_close()
        self.join(timeout=2)


def _git(cwd: Path, *args: str) -> str:
    env = scrub_env(dict(os.environ))
    env.update(
        {
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@localhost",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@localhost",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    completed = subprocess.run(("git", *args), cwd=cwd, env=env, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def _origin(tmp: Path) -> tuple[Path, str]:
    origin = tmp / "origin"
    (origin / "src").mkdir(parents=True)
    (origin / "src" / "widget.py").write_bytes(b"def add(left, right):\n    return 0\n")
    (origin / "src" / "test_widget.py").write_text(
        "import unittest\nfrom widget import add\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_add(self):\n"
        "        self.assertEqual(add(1, 1), 2)\n",
        encoding="utf-8",
    )
    _git(origin, "-c", "core.autocrlf=false", "init", "-b", "dev")
    _git(origin, "add", "src")
    _git(origin, "commit", "-m", "base")
    return origin, _git(origin, "rev-parse", "HEAD")


def _script(tmp: Path, *, fail_until: int) -> Path:
    path = tmp / "worker.py"
    path.write_text(
        "import pathlib, sys\n"
        "count = pathlib.Path('attempts.txt')\n"
        "n = int(count.read_text()) + 1 if count.exists() else 1\n"
        "count.write_text(str(n))\n"
        "print('NOISE', file=sys.stderr)\n"
        f"if n < {fail_until}:\n"
        "    raise SystemExit(1)\n"
        "pathlib.Path('widget.py').write_bytes(b'def add(left, right):\\n    return left + right\\n')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    return path


def _attestation(sha: str, *, nonce: str = "nonce-1", expires: int = 5_000, **overrides: object) -> ManagerAttestation:
    raw: dict[str, object] = {
        "principal_id": "vibe-1",
        "role": "vibe",
        "audience": "worker-1",
        "owner": "cwall5640",
        "repo": "fixture",
        "issue_number": 9,
        "issue_node_id": "NODE9",
        "base_branch": "dev",
        "base_sha": sha,
        "updated_at": "2026-11-09T02:00:00Z",
        "nonce": nonce,
        "expires_at": expires,
        "decision": "assign",
        "signature": "",
    }
    raw.update(overrides)
    return sign_attestation(MANAGER, ManagerAttestation(**raw))  # type: ignore[arg-type]


def _write_inbox(inbox: Path, attestation: ManagerAttestation) -> None:
    inbox.mkdir(exist_ok=True)
    os.chmod(inbox, 0o700)
    (inbox / "9.json").write_text(
        json.dumps(attestation.signed_body() | {"signature": attestation.signature}, sort_keys=True),
        encoding="utf-8",
    )


def _sensors(tmp: Path, value: str = "1") -> tuple[Path, Path, Path]:
    tmp.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in ("power", "session", "network"):
        path = tmp / name
        path.write_text(value + "\n", encoding="utf-8")
        paths.append(path)
    return paths[0], paths[1], paths[2]


def _candidate(
    tmp: Path, api: FixtureApi, sha: str, script: Path, *, enabled: bool = True, name: str = "run"
) -> AssignmentCandidate:
    url = api.start_url()
    slot = tmp / name
    state = slot / "state"
    power, session, network = _sensors(slot)
    secrets = slot / "secrets" / "values"
    prepare_secret_file(secrets, PUBLISH)
    bare = slot / "bare.git"
    bare.parent.mkdir(parents=True, exist_ok=True)
    _git(slot, "init", "--bare", str(bare))
    _write_inbox(slot / "inbox", _attestation(sha))
    verifier = ManagerVerifier(
        {"vibe-1": MANAGER},
        audience="worker-1",
        now=1_000,
        state_dir=state,
    )
    return AssignmentCandidate(
        enabled=enabled,
        owner="cwall5640",
        repo="fixture",
        api=GitHubHttpClient(url, "read-token", timeout=5),
        paths=CandidatePaths(
            state_dir=state,
            source_repo=tmp / "origin",
            workspace=slot / "workspace",
            secrets_file=secrets,
            inbox=slot / "inbox",
            power_file=power,
            session_file=session,
            network_file=network,
            local_remote=bare,
        ),
        verifier=verifier,
        operator_id="operator",
        reviewer_id="reviewer",
        allowed_command=(sys.executable, str(script)),
        command_cwd="src",
    )


def test_disabled_candidate_does_not_start(tmp_path: Path) -> None:
    origin, sha = _origin(tmp_path)
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), enabled=False)
        with pytest.raises(Disabled):
            candidate.run_once()
    finally:
        api.stop()
    assert origin.is_dir()


def test_real_repair_loop_resolves_git_head_and_opens_pr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", PUBLISH)
    monkeypatch.setenv("FCC_PUBLISH_TOKEN", "other-publish")
    _origin(tmp_path)
    _, sha = tmp_path / "origin", ""
    sha = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=tmp_path / "origin", text=True).strip()
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=3))
        result = candidate.run_once()
    finally:
        api.stop()
    assert result["status"] == "returned_for_review"
    assert result["merged"] is False
    assert result["repair_attempts"] == 2
    assert result["head_sha"] != sha
    assert str(result["head_sha"]) in api.bodies[0]
    assert api.posts[0][0].endswith("/pulls")
    assert api.posts[0][1] == f"Bearer {PUBLISH}"
    assert not any(path.endswith("/rerun") for path, _auth in api.posts)
    bare_head = subprocess.check_output(
        ("git", "--git-dir", str(tmp_path / "run" / "bare.git"), "rev-parse", result["branch"]),
        text=True,
    ).strip()
    assert bare_head == result["head_sha"]
    assert result["logs"][0]["exit_code"] == 1
    assert result["logs"][-1]["exit_code"] == 0
    assert "NOISE" in result["logs"][-1]["stderr"]
    mode = (tmp_path / "run" / "state" / "claims" / "claims.json").stat().st_mode
    assert mode & 0o077 == 0


def test_missing_label_forged_expired_revoked_replay_and_wrong_repo(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=tmp_path / "origin", text=True).strip()
    api = FixtureApi(sha)
    api.labels = []
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1))
        assert candidate.run_once()["status"] == "idle"
    finally:
        api.stop()
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1))
        forged = _attestation(sha, nonce="forged")
        inbox = tmp_path / "run" / "inbox" / "9.json"
        raw = json.loads(inbox.read_text(encoding="utf-8"))
        raw["signature"] = "0" * 64
        raw["nonce"] = "forged"
        inbox.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ApprovalInvalid):
            candidate.run_once()
        assert forged.signature != raw["signature"]
    finally:
        api.stop()
    verifier = ManagerVerifier({"vibe-1": MANAGER}, audience="worker-1", now=9_000, state_dir=tmp_path / "late")
    with pytest.raises(ApprovalInvalid, match="expired"):
        verifier.verify(_attestation(sha, expires=10), node_id="NODE9", base_sha=sha, owner="cwall5640", repo="fixture")
    revoked = ManagerVerifier(
        {"vibe-1": MANAGER},
        audience="worker-1",
        now=1_000,
        state_dir=tmp_path / "revoked",
        revocations={"nonce-x"},
    )
    with pytest.raises(ApprovalInvalid, match="revoked"):
        revoked.verify(_attestation(sha, nonce="nonce-x"), node_id="NODE9", base_sha=sha, owner="cwall5640", repo="fixture")
    once = ManagerVerifier({"vibe-1": MANAGER}, audience="worker-1", now=1_000, state_dir=tmp_path / "once")
    attestation = _attestation(sha, nonce="once")
    once.verify(attestation, node_id="NODE9", base_sha=sha, owner="cwall5640", repo="fixture")
    once.consume_nonce("once")
    again = ManagerVerifier({"vibe-1": MANAGER}, audience="worker-1", now=1_000, state_dir=tmp_path / "once")
    with pytest.raises(ApprovalInvalid, match="already used"):
        again.verify(attestation, node_id="NODE9", base_sha=sha, owner="cwall5640", repo="fixture")
    mismatch = _attestation(sha, repo="other")
    mismatch_verifier = ManagerVerifier({"vibe-1": MANAGER}, audience="worker-1", now=1_000, state_dir=tmp_path / "repo")
    with pytest.raises(ApprovalInvalid):
        mismatch_verifier.verify(mismatch, node_id="NODE9", base_sha=sha, owner="cwall5640", repo="fixture")


def test_retry_budget_security_denial_false_ci_and_cancel(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=tmp_path / "origin", text=True).strip()
    api = FixtureApi(sha)
    try:
        stopped = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=99), name="stop").run_once()
    finally:
        api.stop()
    assert stopped["status"] == "stopped"
    assert stopped["repair_attempts"] == 2
    assert api.posts == []
    api = FixtureApi(sha)
    try:
        denied = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="deny")
        denied.allowed_command = ("git", "push")
        with pytest.raises(Forbidden):
            denied.run_once()
        assert denied.ledger.get("cwall5640/fixture#9")["status"] == "blocked"
        assert denied.ledger.get("cwall5640/fixture#9")["repairs"] == 0
    finally:
        api.stop()
    api = FixtureApi(sha)
    api.fail_checks = True
    try:
        held = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="ci").run_once()
    finally:
        api.stop()
    assert held["status"] == "ci_hold"
    assert held["ci"] == "failure"
    assert held["merged"] is False
    api = FixtureApi(sha)
    try:
        cancel = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="cancel")
        _write_inbox(tmp_path / "inbox-cancel", _attestation(sha, nonce="cancel", decision="cancel"))
        cancel.paths = CandidatePaths(
            state_dir=cancel.paths.state_dir,
            source_repo=cancel.paths.source_repo,
            workspace=tmp_path / "unused-workspace",
            secrets_file=cancel.paths.secrets_file,
            inbox=tmp_path / "inbox-cancel",
            power_file=cancel.paths.power_file,
            session_file=cancel.paths.session_file,
            network_file=cancel.paths.network_file,
            local_remote=cancel.paths.local_remote,
        )
        assert cancel.run_once()["status"] == "cancelled"
        assert not (tmp_path / "unused-workspace").exists()
    finally:
        api.stop()


def test_queue_claim_concurrency_and_stale_recovery(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=tmp_path / "origin", text=True).strip()
    api = FixtureApi(sha)
    try:
        queued = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1))
        queued.paths.power_file.write_text("0\n", encoding="utf-8")
        result = queued.run_once()
        assert result["status"] == "queue_sleep"
        assert (tmp_path / "run" / "state" / "queue" / "queue.json").is_file()
        assert admit_machine(queued.probe.read()) == "queue_sleep"
    finally:
        api.stop()
    ledger = ClaimLedger(tmp_path / "ledger")
    first = ledger.claim("cwall5640/fixture#9", "worker-1", sha)
    second = ledger.claim("cwall5640/fixture#9", "worker-1", sha)
    assert first == second
    other = ClaimLedger(tmp_path / "ledger-2")
    other.claim("one", "worker-1", "a" * 40)
    with pytest.raises(Conflict):
        other.claim("two", "worker-1", "b" * 40)
    stale = ClaimLedger(tmp_path / "stale")
    stale.claim("task", "worker-1", "a" * 40)
    with pytest.raises(ApprovalInvalid):
        stale.claim("task", "worker-1", "b" * 40)
    recovered = stale.claim("task", "worker-1", "b" * 40)
    assert recovered["base_sha"] == "b" * 40
    assert recovered["status"] == "active"


def test_secret_file_symlink_and_model_env(tmp_path: Path) -> None:
    path = tmp_path / "secrets" / "values"
    prepare_secret_file(path, PUBLISH)
    loaded = load_secret_file(path)
    assert loaded.get("github_publish") == PUBLISH
    assert "publish" not in repr(loaded)
    os.chmod(path, 0o644)
    with pytest.raises(Forbidden):
        load_secret_file(path)
    os.chmod(path, 0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(Forbidden):
        load_secret_file(link)
    from free_claude_code.assignments.workflow import ManagerVerifier

    verifier = ManagerVerifier({"vibe-1": MANAGER}, audience="worker-1", now=1, state_dir=tmp_path / "redact")
    assert "manager-verify-key" not in repr(verifier)
    assert not hasattr(verifier, "sign")


def test_model_launcher_does_not_receive_publisher_token(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=tmp_path / "origin", text=True).strip()
    api = FixtureApi(sha)
    seen: dict[str, object] = {}

    def spawn(argv: tuple[str, ...], env: dict[str, str], workspace: Path) -> None:
        seen["argv"] = argv
        seen["env"] = env
        seen["workspace"] = workspace

    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1))
        candidate.model_spawn = spawn
        candidate.grant_key = "grant-key"
        candidate.now = 1_000

        def factory(manifest: object) -> ModelGrant:
            return sign_grant(
                "grant-key",
                ModelGrant(
                    manifest.manifest_id,  # type: ignore[attr-defined]
                    f"{manifest.owner}/{manifest.repo}",  # type: ignore[attr-defined]
                    manifest.base_sha,  # type: ignore[attr-defined]
                    manifest.issue_revision,  # type: ignore[attr-defined]
                    5_000,
                    ("implement",),
                    "",
                ),
            )

        candidate.model_grant_factory = factory
        result = candidate.run_once()
    finally:
        api.stop()
    assert result["status"] == "returned_for_review"
    assert PUBLISH not in seen["env"].values()  # type: ignore[union-attr]
    assert "GITHUB_TOKEN" not in seen["env"]
    assert "--dangerously-skip-permissions" not in seen["argv"]


def test_startup_install_is_disabled_and_package_is_real() -> None:
    assert cli_main(["show-contract"]) == 0
    assert cli_main(["activate"]) == 2
    assert candidate_main(["run-once"]) == 2
    assert "blocked_symmetric_key_can_mint" in CAPABILITY_BOUNDARY["unattended_manager_trust"]
    root = Path("packaging/assignment-candidate")
    script = (root / "windows" / "Invoke-AssignmentCandidate.ps1").read_text(encoding="utf-8")
    assert "\r" not in script
    assert "ExecutionPolicy" not in script
    assert "python -c" not in script
    assert "free_claude_code.assignments.candidate" in script
    plan = json.loads((root / "activation-rollback.json").read_text(encoding="utf-8"))
    assert plan["executed"] is False
    installed = install_disabled_startup(Path("/tmp") / "fcc-candidate-install-disabled")
    assert json.loads(installed.read_text(encoding="utf-8"))["enabled"] is False
    assert json.loads(installed.read_text(encoding="utf-8"))["registered_with_os"] is False


@pytest.mark.skip(reason="Windows DACL was not executed on this Linux runner; not a security pass")
def test_windows_dacl_native() -> None:
    raise AssertionError("native DACL must not be reported as a cloud pass")


@pytest.mark.skip(reason="Windows reparse points were not created; not a security pass")
def test_windows_reparse_native() -> None:
    raise AssertionError("native reparse must not be reported as a cloud pass")
