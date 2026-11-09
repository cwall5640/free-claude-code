# SPDX-License-Identifier: AGPL-3.0-only
"""Assignment candidate against local git, fixture HTTP, and one local HTTPS remote."""

import base64
import json
import os
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import pytest

from free_claude_code.assignments.candidate import main as candidate_main
from free_claude_code.assignments.cli import main as cli_main
from free_claude_code.assignments.errors import ApprovalInvalid, Conflict, Disabled, Forbidden, MergeRejected
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.grants import ModelGrant, sign_grant
from free_claude_code.assignments.managers import load_manager_config
from free_claude_code.assignments.publisher import feature_branch, publish_feature, refuse_push_ref
from free_claude_code.assignments.secrets import load_secret_file, write_secret_file
from free_claude_code.assignments.verdict import verify_verdict
from free_claude_code.assignments.workflow import (
    ACTOR_BARE,
    CAPABILITY_BOUNDARY,
    DEFAULT_WAITING_LABEL,
    AssignmentCandidate,
    CandidatePaths,
    ClaimLedger,
    DurableQueue,
    ManagerAttestation,
    ManagerVerifier,
    _comment_payload,
    _private_dir,
    admit_machine,
    assert_reviewer_is_not_author,
    assert_routing_label,
    install_disabled_startup,
    prepare_secret_file,
)
from tests.assignments.manager_sign import new_key, sign_attestation

PUBLISH = "publish-token-value"
VIBE_SECRET, VIBE_PUBLIC = new_key()
WAITING = DEFAULT_WAITING_LABEL


class FixtureApi(threading.Thread):
    def __init__(self, sha: str) -> None:
        super().__init__(daemon=True)
        self.sha = sha
        self.fail_checks = False
        self.labels = [WAITING]
        self.comments: list[dict[str, str]] = []
        self.author = "someone"
        self.pusher = ""
        self.pr_sha = sha
        self.pr_sha_next = sha
        self.pr_reads = 0
        self.permissions = {"admin": False, "maintain": False, "pull": True, "push": True, "triage": False}
        self.posts: list[tuple[str, str]] = []
        self.bodies: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                path = self.path
                if "labels=" in path:
                    requested = unquote(path.split("labels=", 1)[1].split("&", 1)[0])
                    if requested not in outer.labels:
                        self._json([])
                    else:
                        self._json([{"number": 9, "labels": [{"name": requested}]}])
                    return
                if path.endswith("/comments"):
                    self._json(outer.comments)
                    return
                if path.endswith("/pulls/9"):
                    outer.pr_reads += 1
                    current = outer.pr_sha if outer.pr_reads == 1 else outer.pr_sha_next
                    head: dict[str, object] = {"sha": current, "ref": "claude1/fix-add"}
                    if outer.pusher:
                        head["user"] = {"login": outer.pusher}
                    self._json({"number": 9, "user": {"login": outer.author}, "head": head})
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
                if self.path.endswith("/comments") or self.path.endswith("/labels"):
                    self._json({})
                    return
                self.send_error(404)

            def do_DELETE(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

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


class _SSLServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], handler: type, cert: Path, key: Path) -> None:
        super().__init__(address, handler)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)

    def get_request(self) -> tuple[object, object]:
        sock, addr = super().get_request()
        return self.ctx.wrap_socket(sock, server_side=True), addr


class GitHttps(threading.Thread):
    """Local smart-HTTP remote. The publish token is accepted only as a header."""

    def __init__(self, root: Path, token: str) -> None:
        super().__init__(daemon=True)
        self.root = root
        self.token = token
        self.paths: list[str] = []
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        cert_dir = root / "certs"
        cert_dir.mkdir(parents=True)
        self.cert = cert_dir / "cert.pem"
        key = cert_dir / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(self.cert),
                "-days",
                "2",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        self.bare = root / "repo.git"
        subprocess.run(["git", "init", "--bare", str(self.bare)], check=True, capture_output=True, env=env)
        subprocess.run(
            ["git", "--git-dir", str(self.bare), "config", "http.receivepack", "true"],
            check=True,
            capture_output=True,
            env=env,
        )
        expected = "Basic " + base64.b64encode(b"x-access-token:" + token.encode()).decode("ascii")
        backend = "/usr/lib/git-core/git-http-backend"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                self._serve()

            def do_POST(self) -> None:  # noqa: N802
                self._serve()

            def _serve(self) -> None:
                outer.paths.append(self.path)
                if self.headers.get("Authorization", "") != expected:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="git"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length) if length else b""
                path, _, query = self.path.partition("?")
                child_env = {
                    "PATH": os.environ.get("PATH", ""),
                    "GIT_PROJECT_ROOT": str(outer.root),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "REQUEST_METHOD": self.command,
                    "PATH_INFO": path,
                    "QUERY_STRING": query,
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(len(body)),
                    "REMOTE_USER": "x-access-token",
                    "REMOTE_ADDR": "127.0.0.1",
                    "SERVER_PROTOCOL": "HTTP/1.1",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                }
                completed = subprocess.run([backend], input=body, capture_output=True, env=child_env, check=False)
                header_blob, sep, rest = completed.stdout.partition(b"\r\n\r\n")
                if not sep:
                    self.send_error(500)
                    return
                status = 200
                extra: list[tuple[str, str]] = []
                for line in header_blob.decode("iso-8859-1").split("\r\n"):
                    if line.lower().startswith("status:"):
                        status = int(line.split(":", 1)[1].strip().split()[0])
                    elif ":" in line:
                        key_name, value = line.split(":", 1)
                        extra.append((key_name.strip(), value.strip()))
                self.send_response(status)
                for key_name, value in extra:
                    self.send_header(key_name, value)
                self.send_header("Content-Length", str(len(rest)))
                self.end_headers()
                if rest:
                    self.wfile.write(rest)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.httpd = _SSLServer(("127.0.0.1", 0), Handler, self.cert, key)

    def run(self) -> None:
        self.httpd.serve_forever()

    def origin(self) -> str:
        self.start()
        host, port = self.httpd.server_address
        return f"https://{host}:{port}/repo.git"

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
    path = tmp / f"worker-{fail_until}.py"
    path.write_text(
        "import pathlib, sys\n"
        "count = pathlib.Path('attempts.txt')\n"
        "n = int(count.read_text()) + 1 if count.exists() else 1\n"
        "count.write_text(str(n))\n"
        "print('NOISE', file=sys.stderr)\n"
        f"if n < {fail_until}:\n"
        "    raise SystemExit(1)\n"
        "pathlib.Path('widget.py').write_text("
        "'def scale(value, factor):\\n    return value * factor\\n', encoding='utf-8')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    return path


def _ok_script(tmp: Path) -> Path:
    path = tmp / "ok.py"
    path.write_text("raise SystemExit(0)\n", encoding="utf-8")
    return path


def _attestation(sha: str, *, nonce: str = "nonce-1", expires: int = 5_000, secret: bytes = VIBE_SECRET, **overrides: object) -> ManagerAttestation:
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
        "task_id": "fix-add",
        "nonce": nonce,
        "expires_at": expires,
        "decision": "assign",
        "signature": "",
    }
    raw.update(overrides)
    return sign_attestation(secret, ManagerAttestation(**raw))  # type: ignore[arg-type]


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


def _verifier(
    directory: Path,
    public: bytes = VIBE_PUBLIC,
    *,
    now: int = 1_000,
    revocations: set[str] | None = None,
    principal: str = "vibe-1",
    role: str = "vibe",
    name: str = "Vibe Coder",
    interim: str = "",
    extra: dict[str, tuple[bytes, str, str, str]] | None = None,
) -> ManagerVerifier:
    keys = {principal: public}
    roles = {principal: role}
    names = {principal: name}
    interim_until = {principal: interim} if interim else {}
    for item_id, (item_key, item_role, item_name, item_interim) in (extra or {}).items():
        keys[item_id] = item_key
        roles[item_id] = item_role
        names[item_id] = item_name
        if item_interim:
            interim_until[item_id] = item_interim
    return ManagerVerifier(
        keys,
        roles=roles,
        display_names=names,
        audience="worker-1",
        now=now,
        state_dir=directory,
        revocations=revocations,
        interim_until=interim_until,
    )


def _check(verifier: ManagerVerifier, attestation: ManagerAttestation, **overrides: str) -> None:
    verifier.verify(
        attestation,
        node_id=overrides.get("node_id", "NODE9"),
        base_sha=overrides.get("base_sha", attestation.base_sha),
        owner=overrides.get("owner", "cwall5640"),
        repo=overrides.get("repo", "fixture"),
        updated_at=overrides.get("updated_at", attestation.updated_at),
    )


def _candidate(
    tmp: Path,
    api: FixtureApi,
    sha: str,
    script: Path,
    *,
    enabled: bool = True,
    name: str = "run",
    publish: GitHttps | None = None,
    interim: str = "",
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
    candidate = AssignmentCandidate(
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
        verifier=_verifier(state, interim=interim),
        operator_id="operator",
        reviewer_id="reviewer",
        allowed_command=(sys.executable, str(script)),
        command_cwd="src",
    )
    if publish is not None:
        candidate.publish_enabled = True
        candidate.publish_origin = publish.origin()
        candidate.publish_ca_file = publish.cert
    return candidate


def _posted_texts(api: FixtureApi) -> list[str]:
    texts: list[str] = []
    for body in api.bodies:
        try:
            loaded = json.loads(body)
        except json.JSONDecodeError:
            texts.append(body)
            continue
        if isinstance(loaded, dict) and isinstance(loaded.get("body"), str):
            texts.append(str(loaded["body"]))
        else:
            texts.append(body)
    return texts


def _signed_next(secret: bytes, sha: str) -> str:
    body = f"NEXT: {ACTOR_BARE}\nHEAD: {sha}\n"
    signature = __import__(
        "cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]
    ).Ed25519PrivateKey.from_private_bytes(secret).sign(_comment_payload(body))
    return body + f"SIGNATURE: {signature.hex()}\n— dev:claude1\n"


def test_disabled_candidate_does_not_start(tmp_path: Path) -> None:
    origin, sha = _origin(tmp_path)
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), enabled=False)
        assert candidate.publish_enabled is False
        with pytest.raises(Disabled):
            candidate.run_once()
    finally:
        api.stop()
    assert origin.is_dir()


def test_real_repair_loop_commits_any_allowlisted_edit_and_opens_pr(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    api = FixtureApi(sha)
    git_remote = GitHttps(tmp_path / "git-remote", PUBLISH)
    try:
        candidate = _candidate(
            tmp_path, api, sha, _script(tmp_path, fail_until=3), publish=git_remote, interim="2026-11-11"
        )
        result = candidate.run_once()
    finally:
        api.stop()
        git_remote.stop()
    assert result["status"] == "returned_for_review"
    assert result["merged"] is False
    assert result["repair_attempts"] == 2
    assert result["head_sha"] != sha
    assert result["branch"] == "claude1/fix-add"
    assert result["signed_by"] == "vibe-1"
    assert result["signed_by_name"] == "Vibe Coder"
    assert result["slack"] == f"HANDOFF: fix-add | {result['pr_url']} | {result['head_sha']} | PASS | NEXT: pm"
    assert str(result["head_sha"]) in api.bodies[0]
    assert api.posts[0][0].endswith("/pulls")
    assert api.posts[0][1] == f"Bearer {PUBLISH}"
    assert not any("/reviews" in path for path, _auth in api.posts)
    posted = _posted_texts(api)
    assert any("SIGNED BY: vibe-1 (Vibe Coder)" in body for body in posted)
    assert any("INTERIM UNTIL: 2026-11-11" in body for body in posted)
    assert any(body.rstrip().endswith("— dev:claude1") for body in posted)
    shown = _git(tmp_path / "run" / "workspace", "show", f"{result['head_sha']}:src/widget.py")
    assert "return value * factor" in shown
    assert "return left + right" not in shown
    remote_head = _git(tmp_path / "git-remote", "--git-dir", str(git_remote.bare), "rev-parse", "claude1/fix-add")
    assert remote_head == result["head_sha"]
    assert all(PUBLISH not in path for path in git_remote.paths)
    assert result["logs"][0]["exit_code"] == 1
    assert result["logs"][-1]["exit_code"] == 0
    assert "NOISE" in result["logs"][-1]["stderr"]
    events = (tmp_path / "run" / "state" / "service" / "events.jsonl").read_text(encoding="utf-8")
    assert '"operator_id": "vibe-1"' in events
    assert '"operator_id": "operator"' not in events
    mode = (tmp_path / "run" / "state" / "claims" / "claims.json").stat().st_mode
    assert mode & 0o077 == 0


def test_missing_label_forged_expired_revoked_replay_and_wrong_repo(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    api = FixtureApi(sha)
    api.labels = []
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="missing")
        assert candidate.run_once()["status"] == "not_routed"
        (candidate.paths.inbox / "9.json").unlink()
        assert candidate.run_once()["status"] == "idle"
    finally:
        api.stop()
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="forged")
        inbox = tmp_path / "forged" / "inbox" / "9.json"
        raw = json.loads(inbox.read_text(encoding="utf-8"))
        raw["signature"] = "0" * 128
        inbox.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ApprovalInvalid):
            candidate.run_once()
    finally:
        api.stop()
    verifier = _verifier(tmp_path / "late", now=9_000)
    with pytest.raises(ApprovalInvalid, match="expired"):
        _check(verifier, _attestation(sha, expires=10))
    revoked = _verifier(tmp_path / "revoked", revocations={"nonce-x"})
    with pytest.raises(ApprovalInvalid, match="revoked"):
        _check(revoked, _attestation(sha, nonce="nonce-x"))
    once = _verifier(tmp_path / "once")
    attestation = _attestation(sha, nonce="once")
    _check(once, attestation)
    once.consume_nonce("once")
    again = _verifier(tmp_path / "once")
    with pytest.raises(ApprovalInvalid, match="already used"):
        _check(again, attestation)
    mismatch = _attestation(sha, repo="other")
    with pytest.raises(ApprovalInvalid):
        _check(_verifier(tmp_path / "repo"), mismatch)
    stale_time = _verifier(tmp_path / "updated")
    with pytest.raises(ApprovalInvalid, match="does not match"):
        _check(stale_time, _attestation(sha, nonce="time"), updated_at="1999-01-01T00:00:00Z")


def test_retry_budget_security_denial_false_ci_and_cancel(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
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
    git_remote = GitHttps(tmp_path / "ci-git", PUBLISH)
    try:
        held = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="ci", publish=git_remote).run_once()
    finally:
        api.stop()
        git_remote.stop()
    assert held["status"] == "ci_hold"
    assert held["ci"] == "failure"
    assert held["merged"] is False
    assert held["slack"].endswith("| HOLD | NEXT: pm")
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


def test_queue_recovers_by_node_id_and_lock_expires(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    api = FixtureApi(sha)
    try:
        queued = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1))
        queued.paths.power_file.write_text("0\n", encoding="utf-8")
        result = queued.run_once()
        assert result["status"] == "queue_sleep"
        stored = json.loads((tmp_path / "run" / "state" / "queue" / "queue.json").read_text(encoding="utf-8"))
        assert stored["items"][0]["issue_node_id"] == "NODE9"
        assert stored["items"][0]["issue_number"] == 9
        assert "mac" in stored
        stored["items"][0]["issue_number"] = 99
        (tmp_path / "run" / "state" / "queue" / "queue.json").write_text(json.dumps(stored), encoding="utf-8")
        with pytest.raises(Forbidden, match="queue integrity"):
            queued.queue.pop_matching("NODE9")
        queued.paths.power_file.write_text("1\n", encoding="utf-8")
        fresh = DurableQueue(tmp_path / "fresh-queue")
        fresh.push({"issue_number": 9, "issue_node_id": "NODE9", "reason": "queue_sleep"})
        assert fresh.pop_matching("NODE9")["issue_number"] == 9
        assert fresh.pop_matching("NODE9") is None
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
    claims = json.loads((tmp_path / "stale" / "claims.json").read_text(encoding="utf-8"))
    claims["tasks"]["task"]["status"] = "completed"
    (tmp_path / "stale" / "claims.json").write_text(json.dumps(claims), encoding="utf-8")
    with pytest.raises(Forbidden, match="integrity"):
        stale.get("task")
    locked = ClaimLedger(tmp_path / "locked")
    lock = locked.root / "active.lock"
    lock.write_text(f"{os.getpid()}\n{int(__import__('time').time()) + 100}\nbusy\n", encoding="utf-8")
    with pytest.raises(Conflict, match="already active"):
        locked.claim("live", "worker-1", "a" * 40)
    expired = ClaimLedger(tmp_path / "expired")
    dead = expired.root / "active.lock"
    dead.write_text(f"999999\n{int(__import__('time').time()) + 100}\nold\n", encoding="utf-8")
    recovered_lock = expired.claim("after-crash", "worker-1", "c" * 40)
    assert recovered_lock["status"] == "active"
    leased = ClaimLedger(tmp_path / "leased")
    lease = leased.root / "active.lock"
    lease.write_text(f"{os.getpid()}\n1\nold\n", encoding="utf-8")
    assert leased.claim("after-lease", "worker-1", "d" * 40)["status"] == "active"


def test_secret_file_symlink_scrub_and_model_env(tmp_path: Path) -> None:
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
    cleaned = scrub_env({"PATH": "/bin", "FCC_PUBLISH_TOKEN": PUBLISH, "FCC_ASKPASS_FILE": "/tmp/token"})
    assert "FCC_PUBLISH_TOKEN" not in cleaned
    assert "FCC_ASKPASS_FILE" not in cleaned
    verifier = _verifier(tmp_path / "redact")
    assert VIBE_PUBLIC.hex() not in repr(verifier)
    assert not hasattr(verifier, "sign")
    for module in Path("src/free_claude_code/assignments").glob("*.py"):
        if module.name == "verdict_sign.py":
            continue
        text = module.read_text(encoding="utf-8")
        assert "Ed25519PrivateKey" not in text
        assert "sign_attestation" not in text


def test_model_launcher_uses_proxy_auth_from_the_secret_file(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    api = FixtureApi(sha)
    git_remote = GitHttps(tmp_path / "model-git", PUBLISH)
    seen: dict[str, object] = {}

    def spawn(argv: tuple[str, ...], env: dict[str, str], workspace: Path) -> None:
        seen["argv"] = argv
        seen["env"] = env
        seen["workspace"] = workspace

    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), publish=git_remote)
        write_secret_file(
            candidate.paths.secrets_file,
            {
                "github_read": "read-token",
                "github_ci": "ci-token",
                "github_publish": PUBLISH,
                "grant_key": "grant-key",
                "proxy_auth": "proxy-from-secret-file",
            },
        )
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
        git_remote.stop()
    assert result["status"] == "returned_for_review"
    env = seen["env"]
    assert isinstance(env, dict)
    assert PUBLISH not in env.values()
    assert "GITHUB_TOKEN" not in env
    assert "FCC_PUBLISH_TOKEN" not in env
    assert "proxy-from-secret-file" in env.values()
    assert "proxy-token" not in env.values()
    assert "--dangerously-skip-permissions" not in seen["argv"]


def test_routing_comments_self_review_and_manager_config(tmp_path: Path) -> None:
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    with pytest.raises(Forbidden):
        assert_routing_label("dev:claude1")
    with pytest.raises(Forbidden):
        assert_routing_label("status:ready")
    api = FixtureApi(sha)
    try:
        candidate = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="devlabel")
        candidate.waiting_label = "dev:claude1"
        with pytest.raises(Forbidden, match="dev or status"):
            candidate.run_once()
        assert api.posts == []
        with pytest.raises(Forbidden):
            candidate.api.replace_waiting_label("cwall5640", "fixture", 9, remove=WAITING, add="dev:claude1", timeout=5)
        assert api.posts == []
    finally:
        api.stop()
    api = FixtureApi(sha)
    api.labels = []
    api.comments = [{"body": f"NEXT: {ACTOR_BARE}\nHEAD: {sha}\n— dev:claude1\n"}]
    try:
        unsigned = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="unsigned")
        assert unsigned.run_once()["status"] == "not_routed"
    finally:
        api.stop()
    api = FixtureApi(sha)
    api.labels = []
    api.comments = [{"body": _signed_next(VIBE_SECRET, "0" * 40)}]
    try:
        stale = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="stale-comment")
        assert stale.run_once()["status"] == "stale_head"
    finally:
        api.stop()
    api = FixtureApi(sha)
    api.author = ACTOR_BARE
    try:
        review = _candidate(tmp_path, api, sha, _ok_script(tmp_path), name="self")
        with pytest.raises(Forbidden, match="authored or pushed"):
            review.review_pull(9)
        assert api.posts == []
    finally:
        api.stop()
    api = FixtureApi(sha)
    api.author = "Minerva"
    secret, public = new_key()
    try:
        review = _candidate(tmp_path, api, sha, _ok_script(tmp_path), name="minerva-pr")
        key_path = tmp_path / "verdict.key"
        key_path.write_bytes(secret)
        os.chmod(key_path, 0o600)
        review.verdict_key_file = key_path
        result = review.review_pull(9)
        assert result["verdict"] == "PASS"
        assert result["merged"] is False
        assert not any("/reviews" in path for path, _auth in api.posts)
        body = _posted_texts(api)[-1]
        signature = bytes.fromhex(next(line.split(":", 1)[1].strip() for line in body.splitlines() if line.startswith("SIGNATURE:")))
        assert verify_verdict(
            public,
            {
                "verdict": "PASS",
                "head_sha": sha,
                "findings": "local checks passed",
                "limitations": "local runners only",
            },
            signature,
        )
    finally:
        api.stop()
    with pytest.raises(Forbidden, match="own pull request"):
        assert_reviewer_is_not_author(author_login="Minerva", reviewer_login="Minerva")
    assert_reviewer_is_not_author(author_login="Minerva", reviewer_login=ACTOR_BARE)
    example = load_manager_config(Path("packaging/assignment-candidate/managers.example.json"))
    assert [item.principal_id for item in example] == ["vibe-coder", "project-manager", "minerva"]
    assert example[2].interim_until == "2026-11-11"
    for module in ("workflow.py", "managers.py", "ed25519_verify.py", "verdict.py"):
        assert "Minerva" not in Path("src/free_claude_code/assignments", module).read_text(encoding="utf-8")
    kept_secret, kept_public = new_key()
    removed_secret, removed_public = new_key()
    stranger_secret, _stranger_public = new_key()
    config = {
        "managers": [
            {
                "principal_id": "vibe-coder",
                "role": "vibe",
                "display_name": "Vibe Coder",
                "github_login": "VibeCoder",
                "public_key_hex": kept_public.hex(),
            },
            {
                "principal_id": "project-manager",
                "role": "project_manager",
                "display_name": "Project Manager",
                "github_login": "Grok",
                "public_key_hex": new_key()[1].hex(),
            },
            {
                "principal_id": "minerva",
                "role": "project_manager",
                "display_name": "Minerva",
                "github_login": "Minerva",
                "public_key_hex": removed_public.hex(),
                "interim_until": "2026-11-11",
            },
        ]
    }
    path = tmp_path / "managers.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    full = load_manager_config(path)
    full_verifier = _verifier(
        tmp_path / "full",
        kept_public,
        principal="vibe-coder",
        extra={item.principal_id: (item.public_key, item.role, item.display_name, item.interim_until) for item in full},
    )
    assigned = _attestation(sha, secret=removed_secret, principal_id="minerva", role="project_manager", nonce="interim")
    _check(full_verifier, assigned)
    config["managers"] = config["managers"][:2]
    path.write_text(json.dumps(config), encoding="utf-8")
    reduced = load_manager_config(path)
    assert "minerva" not in {item.principal_id for item in reduced}
    reduced_verifier = _verifier(
        tmp_path / "reduced",
        kept_public,
        principal="vibe-coder",
        extra={item.principal_id: (item.public_key, item.role, item.display_name, item.interim_until) for item in reduced},
    )
    with pytest.raises(Forbidden, match="authorized manager"):
        _check(reduced_verifier, assigned)
    unknown = _attestation(sha, secret=stranger_secret, principal_id="stranger", nonce="unknown")
    with pytest.raises(Forbidden, match="authorized manager"):
        _check(reduced_verifier, unknown)
    forged = _attestation(sha, secret=removed_secret, principal_id="vibe-coder", nonce="wrong-key")
    with pytest.raises(ApprovalInvalid, match="signature"):
        _check(reduced_verifier, forged)


def test_publisher_refuses_protected_refs_and_stays_disabled(tmp_path: Path) -> None:
    with pytest.raises(MergeRejected):
        refuse_push_ref("refs/heads/main")
    with pytest.raises(MergeRejected):
        refuse_push_ref("refs/heads/master")
    with pytest.raises(MergeRejected):
        refuse_push_ref("refs/tags/v1", tags=True)
    with pytest.raises(MergeRejected):
        feature_branch("main")
    with pytest.raises(Disabled):
        publish_feature(
            enabled=False,
            secrets_file=tmp_path / "missing",
            workspace=tmp_path,
            task_id="fix-add",
            origin="https://127.0.0.1/repo.git",
            api_base="http://127.0.0.1",
            owner="cwall5640",
            repo="fixture",
            base_branch="dev",
            title="t",
            body="b",
            head_sha="a" * 40,
            author_id="dev:claude1",
            reviewer_id="vibe-1",
            manifest_id="m",
        )
    with pytest.raises(MergeRejected):
        publish_feature(
            enabled=True,
            secrets_file=tmp_path / "missing",
            workspace=tmp_path,
            task_id="fix-add",
            origin="https://127.0.0.1/repo.git",
            api_base="http://127.0.0.1",
            owner="cwall5640",
            repo="fixture",
            base_branch="dev",
            title="t",
            body="b",
            head_sha="a" * 40,
            author_id="dev:claude1",
            reviewer_id="vibe-1",
            manifest_id="m",
            force=True,
        )


def test_windows_owner_check_is_used_for_private_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "free_claude_code.assignments.workflow._platform_name",
        lambda: "nt",
    )
    calls: list[Path] = []

    def deny(path: Path) -> bool:
        calls.append(path)
        return False

    monkeypatch.setattr("free_claude_code.assignments.windows_acl.file_is_current_user_only", deny)
    with pytest.raises(Forbidden, match="current user"):
        _private_dir(tmp_path / "state")
    assert calls


def test_startup_install_is_disabled_and_package_is_real() -> None:
    assert cli_main(["show-contract"]) == 0
    assert cli_main(["activate"]) == 2
    assert candidate_main(["run-once"]) == 2
    assert CAPABILITY_BOUNDARY["manager_signatures"] == "ed25519_public_key_only"
    assert CAPABILITY_BOUNDARY["text_signature"] == "convention_only_not_authority"
    assert CAPABILITY_BOUNDARY["manager_set"] == "config_file_of_pinned_public_keys"
    root = Path("packaging/assignment-candidate")
    script = (root / "windows" / "Invoke-AssignmentCandidate.ps1").read_text(encoding="utf-8")
    assert "\r" not in script
    assert "ExecutionPolicy" not in script
    assert "python -c" not in script
    assert "OK stage=show-contract exit=0" not in script
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


@pytest.mark.skip(reason="Windows PowerShell was not executed on this Linux runner; not a security pass")
def test_windows_powershell_show_contract() -> None:
    raise AssertionError("native PowerShell must not be reported as a cloud pass")
