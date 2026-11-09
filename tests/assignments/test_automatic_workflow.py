# SPDX-License-Identifier: AGPL-3.0-only
"""Assignment candidate against local git, fixture HTTP, and one local HTTPS remote."""

import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import pytest

from free_claude_code.assignments.candidate import main as candidate_main
from free_claude_code.assignments.cli import main as cli_main
from free_claude_code.assignments.errors import ApprovalInvalid, Conflict, Disabled, Forbidden, MergeRejected
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.github_http import GitHubHttpClient
from free_claude_code.assignments.handoff import actor_label, assert_handoff_label, load_actor_map
from free_claude_code.assignments.identity import WorkerIdentity, default_worker_identity, load_worker_identity
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
PINNED_ORIGIN = "https://github.com/cwall5640/fixture.git"


def _path_number(path: str) -> int | None:
    tail = path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if tail.isdigit():
        return int(tail)
    return None


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
        self.has_pull = True
        self.token_login = "claude1"
        self.issue_labels: dict[int, list[str]] | None = None
        self.permissions = {"admin": False, "maintain": False, "pull": True, "push": True, "triage": False}
        self.posts: list[tuple[str, str]] = []
        self.bodies: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                path = self.path
                if path.split("?", 1)[0] == "/user":
                    self._json({"login": outer.token_login})
                    return
                if "labels=" in path:
                    requested = unquote(path.split("labels=", 1)[1].split("&", 1)[0])
                    self._json(outer.labeled_issues(requested))
                    return
                if path.endswith("/comments"):
                    self._json(outer.comments)
                    return
                number = _path_number(path)
                if "/pulls/" in path and number is not None:
                    if not outer.has_pull or number not in outer.pull_numbers():
                        self.send_error(404)
                        return
                    outer.pr_reads += 1
                    current = outer.pr_sha if outer.pr_reads == 1 else outer.pr_sha_next
                    head: dict[str, object] = {"sha": current, "ref": f"review/{number}"}
                    if outer.pusher:
                        head["user"] = {"login": outer.pusher}
                    self._json({"number": number, "user": {"login": outer.author}, "head": head})
                    return
                if "/issues/" in path and number is not None and outer.serves_issue(number):
                    self._json(outer.issue_payload(number))
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
        if not self.is_alive():
            self.start()
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def serves_issue(self, number: int) -> bool:
        if self.issue_labels is not None:
            return number in self.issue_labels
        return number == 9

    def pull_numbers(self) -> set[int]:
        if not self.has_pull:
            return set()
        if self.issue_labels is not None:
            return set(self.issue_labels)
        return {9}

    def labels_for(self, number: int) -> list[str]:
        if self.issue_labels is not None:
            return list(self.issue_labels.get(number, []))
        return list(self.labels) if number == 9 else []

    def labeled_issues(self, label: str) -> list[dict[str, object]]:
        if self.issue_labels is not None:
            numbers = [number for number, names in sorted(self.issue_labels.items()) if label in names]
        elif label in self.labels:
            numbers = [9]
        else:
            numbers = []
        return [{"number": number, "labels": [{"name": label}]} for number in numbers]

    def issue_payload(self, number: int) -> dict[str, object]:
        return {
            "number": number,
            "title": "Fix add",
            "body": "untrusted text is not a command",
            "state": "open",
            "updated_at": "2026-11-09T02:00:00Z",
            "node_id": f"NODE{number}",
            "labels": [{"name": name} for name in self.labels_for(number)],
        }

    def stop(self) -> None:
        if self.is_alive():
            self.httpd.shutdown()
            self.join(timeout=2)
        self.httpd.server_close()


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
                _resolve_tool("openssl"),
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
        git = _resolve_tool("git")
        subprocess.run([git, "init", "--bare", str(self.bare)], check=True, capture_output=True, env=env)
        subprocess.run(
            [git, "--git-dir", str(self.bare), "config", "http.receivepack", "true"],
            check=True,
            capture_output=True,
            env=env,
        )
        expected = "Basic " + base64.b64encode(b"x-access-token:" + token.encode()).decode("ascii")
        backend = _git_http_backend()
        if backend is None:
            pytest.skip("git-http-backend was not found via git --exec-path")
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
        if not self.is_alive():
            self.start()
        host, port = self.httpd.server_address
        return f"https://{host}:{port}/repo.git"

    def stop(self) -> None:
        if self.is_alive():
            self.httpd.shutdown()
            self.join(timeout=2)
        self.httpd.server_close()


def _resolve_tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        relatives = {
            "git": ("Git\\cmd\\git.exe", "Git\\bin\\git.exe"),
            "openssl": ("Git\\usr\\bin\\openssl.exe", "Git\\mingw64\\bin\\openssl.exe"),
        }
        for relative in relatives.get(name, ()):
            candidate = Path(program_files) / relative
            if candidate.is_file():
                return str(candidate)
    if name in {"python", "python3"}:
        return sys.executable
    return name


def _git_http_backend() -> str | None:
    """Locate git-http-backend. Git for Windows keeps it in `git --exec-path`, not on PATH."""

    names = ("git-http-backend.exe", "git-http-backend") if os.name == "nt" else ("git-http-backend",)
    git = _resolve_tool("git")
    if Path(git).is_file() or shutil.which(git):
        completed = subprocess.run(
            [git, "--exec-path"],
            check=False,
            capture_output=True,
            text=True,
            env={
                "PATH": os.environ.get("PATH", ""),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
        )
        if completed.returncode == 0 and completed.stdout.strip():
            exec_path = Path(completed.stdout.strip())
            for name in names:
                candidate = exec_path / name
                if candidate.is_file():
                    return str(candidate)
    for candidate in (
        Path("/usr/lib/git-core/git-http-backend"),
        Path("/usr/libexec/git-core/git-http-backend"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


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
    completed = subprocess.run(
        (_resolve_tool("git"), *args), cwd=cwd, env=env, check=True, capture_output=True, text=True
    )
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


def _write_inbox(inbox: Path, attestation: ManagerAttestation, number: int = 9) -> None:
    inbox.mkdir(exist_ok=True)
    os.chmod(inbox, 0o700)
    (inbox / f"{number}.json").write_text(
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
    handoff = {principal: _handoff_actor(name)}
    for item_id, (item_key, item_role, item_name, item_interim) in (extra or {}).items():
        keys[item_id] = item_key
        roles[item_id] = item_role
        names[item_id] = item_name
        handoff[item_id] = _handoff_actor(item_name)
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
        handoff_actors=handoff,
    )


def _handoff_actor(display_name: str) -> str:
    return {"Minerva": "Minerva", "Project Manager": "Grok", "Vibe Coder": "Casey"}.get(display_name, "Casey")


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
    identity: WorkerIdentity | None = None,
    issue_number: int = 9,
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
    worker = identity or default_worker_identity()
    _write_inbox(
        slot / "inbox",
        _attestation(
            sha,
            issue_number=issue_number,
            issue_node_id=f"NODE{issue_number}",
        ),
        issue_number,
    )
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
        identity=worker,
    )
    if publish is not None:
        candidate.publish_enabled = True
        candidate.publish_origin = PINNED_ORIGIN
        candidate.publish_ca_file = publish.cert
        publish.origin()
    return candidate


@contextmanager
def _redirect_pinned_push(git_remote: GitHttps):
    """Rewrite the pinned github.com URL to the local HTTPS remote inside git.

    Real git.exe is used. A .cmd shim on PATH makes CreateProcess reject the
    workspace cwd on Windows (WinError 267).
    """

    local = git_remote.origin()
    keys = ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")
    saved = {key: os.environ.get(key) for key in keys}
    os.environ["GIT_CONFIG_COUNT"] = "1"
    os.environ["GIT_CONFIG_KEY_0"] = f"url.{local}.insteadOf"
    os.environ["GIT_CONFIG_VALUE_0"] = "https://github.com/cwall5640/fixture.git"
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run_published(candidate: AssignmentCandidate, git_remote: GitHttps) -> dict[str, object]:
    with _redirect_pinned_push(git_remote):
        return candidate.run_once()


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
            tmp_path, api, sha, _script(tmp_path, fail_until=3), publish=git_remote
        )
        result = _run_published(candidate, git_remote)
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
    assert result["slack"] == f"HANDOFF: fix-add | {result['pr_url']} | {result['head_sha']} | PASS | NEXT: Casey"
    assert str(result["head_sha"]) in api.bodies[0]
    assert api.posts[0][0].endswith("/pulls")
    assert api.posts[0][1] == f"Bearer {PUBLISH}"
    assert not any("/reviews" in path for path, _auth in api.posts)
    posted = _posted_texts(api)
    assert any("SIGNED BY: vibe-1 (Vibe Coder)" in body for body in posted)
    assert all("INTERIM UNTIL:" not in body for body in posted)
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
    claims = tmp_path / "run" / "state" / "claims" / "claims.json"
    _assert_private_state(claims)


def test_other_state_files_are_private(tmp_path: Path) -> None:
    """Queue, lock, journal, approval, nonce, and startup files are private too."""

    from free_claude_code.assignments.models import Approval
    from free_claude_code.assignments.private_io import atomic_write_private
    from free_claude_code.assignments.store import StateStore

    ledger = ClaimLedger(tmp_path / "state" / "claims")
    ledger.claim("owner/repo#9", "dev:claude1", "a" * 40)
    queue = DurableQueue(tmp_path / "state" / "queue")
    queue.push({"issue_number": 9, "issue_node_id": "node-9"})
    store = StateStore(tmp_path / "state" / "service")
    store.record("owner/repo#9", {"detail": "task log", "status": "started"})
    store.save_approval(
        Approval(
            manifest_id="manifest-1",
            phase="execute",
            operator_id="vibe-1",
            issue_revision="rev",
            base_sha="a" * 40,
            scope_fingerprint="scope",
        )
    )
    verifier = _verifier(tmp_path / "state" / "verifier")
    verifier.consume_nonce("nonce-1")
    install_disabled_startup(tmp_path / "state" / "startup")
    paths = [
        tmp_path / "state" / "claims" / "claims.json",
        tmp_path / "state" / "claims" / "integrity.key",
        tmp_path / "state" / "claims" / "active.lock",
        tmp_path / "state" / "queue" / "queue.json",
        tmp_path / "state" / "queue" / "integrity.key",
        tmp_path / "state" / "service" / "events.jsonl",
        tmp_path / "state" / "verifier" / "nonces.txt",
        tmp_path / "state" / "startup" / "startup-plan.json",
        tmp_path / "state" / "startup" / "enabled",
        *sorted((tmp_path / "state" / "service" / "status").glob("*.json")),
        *sorted((tmp_path / "state" / "service" / "approvals").glob("*.json")),
    ]
    assert len(paths) >= 11
    for path in paths:
        assert path.is_file()
        _assert_private_state(path)
    for directory in (
        tmp_path / "state" / "claims",
        tmp_path / "state" / "queue",
        tmp_path / "state" / "service",
        tmp_path / "state" / "service" / "status",
        tmp_path / "state" / "service" / "approvals",
    ):
        _assert_private_state(directory)

    seen: list[Path] = []
    real_replace = os.replace

    def wrapped(src: str | Path, dst: str | Path) -> None:
        seen.append(Path(src))
        _assert_private_state(Path(src))
        real_replace(src, dst)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(os, "replace", wrapped)
    try:
        atomic_write_private(tmp_path / "state" / "replaced.json", b'{"ok": true}\n')
    finally:
        monkeypatch.undo()
    assert seen
    assert seen[0].name.startswith(".replaced.json.")
    _assert_private_state(tmp_path / "state" / "replaced.json")


def _assert_private_state(path: Path) -> None:
    if sys.platform == "win32":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only

        assert file_is_current_user_only(path)
        return
    assert path.stat().st_mode & 0o077 == 0


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
        held = _run_published(
            _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="ci", publish=git_remote),
            git_remote,
        )
    finally:
        api.stop()
        git_remote.stop()
    assert held["status"] == "ci_hold"
    assert held["ci"] == "failure"
    assert held["merged"] is False
    assert held["slack"].endswith("| HOLD | NEXT: Casey")
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
    if os.name == "nt":
        _assert_windows_reparse_secret(tmp_path)
    else:
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
        if module.name in {"verdict_sign.py", "manager_sign.py"}:
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
        result = _run_published(candidate, git_remote)
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
                "actor": default_worker_identity().actor_name,
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
    assert [item.interim_until for item in example] == ["", "", ""]
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
        feature_branch("main", "claude1")
    with pytest.raises(Forbidden):
        feature_branch("fix-add", "main")
    assert feature_branch("fix-add", "claude2") == "claude2/fix-add"
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
            branch_prefix="claude1",
            comment_signature="— dev:claude1",
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
            branch_prefix="claude1",
            comment_signature="— dev:claude1",
            force=True,
        )
    with pytest.raises(Forbidden, match="github.com"):
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
            branch_prefix="claude1",
            comment_signature="— dev:claude1",
        )


def test_publisher_deletes_the_askpass_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets = tmp_path / "secrets" / "values"
    prepare_secret_file(secrets, PUBLISH)
    api = FixtureApi("a" * 40)
    url = api.start_url()

    def fake_run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert PINNED_ORIGIN in command
        assert PUBLISH not in " ".join(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("free_claude_code.assignments.publisher.subprocess.run", fake_run)
    try:
        created = publish_feature(
            enabled=True,
            secrets_file=secrets,
            workspace=tmp_path,
            task_id="fix-add",
            origin=PINNED_ORIGIN,
            api_base=url,
            owner="cwall5640",
            repo="fixture",
            base_branch="dev",
            title="t",
            body="b",
            head_sha="a" * 40,
            author_id="dev:claude1",
            reviewer_id="vibe-1",
            manifest_id="m",
            branch_prefix="claude1",
            comment_signature="— dev:claude1",
        )
    finally:
        api.stop()
    assert created.startswith("http://127.0.0.1/pull/")
    assert not (tmp_path / "secrets" / "askpass-token").exists()


def test_windows_owner_check_is_used_for_private_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "free_claude_code.assignments.workflow._platform_name",
        lambda: "nt",
    )
    order: list[str] = []

    def harden(path: Path) -> None:
        order.append("harden")

    def allow(path: Path) -> bool:
        order.append("check")
        return True

    monkeypatch.setattr("free_claude_code.assignments.windows_acl.harden_path", harden)
    monkeypatch.setattr("free_claude_code.assignments.windows_acl.file_is_current_user_only", allow)
    created = _private_dir(tmp_path / "state")
    assert created.is_dir()
    assert order == ["harden", "check"]


def test_two_workers_pick_up_only_their_own_lane(tmp_path: Path) -> None:
    from free_claude_code.assignments.identity import validate_worker_identity

    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    api = FixtureApi(sha)
    api.issue_labels = {9: ["waiting:claude1"], 11: ["waiting:claude2"]}
    first = default_worker_identity()
    second_key = tmp_path / "claude2.key"
    secret, _public = new_key()
    second_key.write_bytes(secret)
    os.chmod(second_key, 0o600)
    second = WorkerIdentity(
        actor_name="dev:claude2",
        bare_name="claude2",
        branch_prefix="claude2",
        comment_signature="— dev:claude2",
        waiting_label="waiting:claude2",
        github_login="publisher-bot",
        verdict_key_file=second_key,
    )
    validate_worker_identity(second)
    try:
        claude1 = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="lane1", identity=first)
        claude2 = _candidate(
            tmp_path,
            api,
            sha,
            _script(tmp_path, fail_until=1),
            name="lane2",
            identity=second,
            issue_number=11,
        )
        with pytest.raises(Disabled, match="publisher is disabled"):
            claude1.run_once()
        with pytest.raises(Disabled, match="publisher is disabled"):
            claude2.run_once()
    finally:
        api.stop()
    assert _git(tmp_path / "lane1" / "workspace", "branch", "--show-current") == "claude1/fix-add"
    assert _git(tmp_path / "lane2" / "workspace", "branch", "--show-current") == "claude2/fix-add"
    assert "claude2/" not in _git(tmp_path / "lane1" / "workspace", "branch")
    assert "claude1/" not in _git(tmp_path / "lane2" / "workspace", "branch")
    own = FixtureApi(sha)
    own.author = "claude2"
    own.token_login = "publisher-bot"
    try:
        review = _candidate(tmp_path, own, sha, _ok_script(tmp_path), name="lane2-review", identity=second)
        with pytest.raises(Forbidden, match="authored or pushed"):
            review.review_pull(9)
        own.author = "publisher-bot"
        own.pusher = ""
        with pytest.raises(Forbidden, match="authored or pushed"):
            review.review_pull(9)
    finally:
        own.stop()
    other = FixtureApi(sha)
    other.author = "claude1"
    other.token_login = "publisher-bot"
    try:
        review = _candidate(tmp_path, other, sha, _ok_script(tmp_path), name="lane2-other", identity=second)
        review.verdict_key_file = second_key
        result = review.review_pull(9)
        assert result["verdict"] == "PASS"
        body = _posted_texts(other)[-1]
        assert body.rstrip().endswith("— dev:claude2")
        assert "— dev:claude1" not in body
    finally:
        other.stop()
    pushed = FixtureApi(sha)
    pushed.author = "someone"
    pushed.pusher = "claude1"
    pushed.token_login = "claude1"
    try:
        review = _candidate(tmp_path, pushed, sha, _ok_script(tmp_path), name="lane1-push", identity=first)
        with pytest.raises(Forbidden, match="authored or pushed"):
            review.review_pull(9)
    finally:
        pushed.stop()


def test_handoff_actor_interim_and_pull_head(tmp_path: Path) -> None:
    assert actor_label("Minerva") == "waiting:minerva"
    assert actor_label("Grok") == "waiting:grok"
    assert actor_label("Casey") == "waiting:casey"
    assert actor_label("RPG Dev") == "waiting:rpg-dev"
    assert actor_label("claude3") == "waiting:claude3"
    with pytest.raises(Forbidden, match="unknown handoff"):
        actor_label("pm")
    with pytest.raises(Forbidden, match="unknown handoff"):
        assert_handoff_label("waiting:pm")
    loaded = load_actor_map(Path("packaging/assignment-candidate/handoff-actors.example.json"))
    assert loaded["Minerva"] == "waiting:minerva"
    assert "pm" not in loaded
    example = load_worker_identity(Path("packaging/assignment-candidate/worker.example.json"))
    assert example.bare_name == "claude1"
    managers = load_manager_config(Path("packaging/assignment-candidate/managers.example.json"))
    assert {item.principal_id: item.handoff_actor for item in managers}["minerva"] == "Minerva"
    assert {item.principal_id: item.handoff_actor for item in managers}["project-manager"] == "Grok"
    _origin(tmp_path)
    sha = _git(tmp_path / "origin", "rev-parse", "HEAD")
    before = int(datetime(2026, 11, 11, 15, tzinfo=timezone.utc).timestamp())
    after = int(datetime(2026, 11, 12, tzinfo=timezone.utc).timestamp())
    interim_secret, interim_public = new_key()
    valid = _verifier(
        tmp_path / "before",
        interim_public,
        now=before,
        principal="synthetic-interim",
        role="project_manager",
        name="Synthetic Interim",
        interim="2026-11-11",
    )
    during = _attestation(
        sha,
        secret=interim_secret,
        principal_id="synthetic-interim",
        role="project_manager",
        nonce="during",
        expires=2_000_000_000,
    )
    _check(valid, during)
    expired = _verifier(
        tmp_path / "after",
        interim_public,
        now=after,
        principal="synthetic-interim",
        role="project_manager",
        name="Synthetic Interim",
        interim="2026-11-11",
    )
    with pytest.raises(ApprovalInvalid, match="interim_until"):
        _check(
            expired,
            _attestation(
                sha,
                secret=interim_secret,
                principal_id="synthetic-interim",
                role="project_manager",
                nonce="later",
                expires=2_000_000_000,
            ),
        )
    api = FixtureApi(sha)
    try:
        url = api.start_url()
        slot = tmp_path / "synthetic-handoff"
        state = slot / "state"
        power, session, network = _sensors(slot)
        secrets = slot / "secrets" / "values"
        prepare_secret_file(secrets, PUBLISH)
        posted = AssignmentCandidate(
            enabled=True,
            owner="cwall5640",
            repo="fixture",
            api=GitHubHttpClient(url, "read-token", timeout=5),
            paths=CandidatePaths(
                state_dir=state,
                source_repo=tmp_path / "origin",
                workspace=slot / "workspace",
                secrets_file=secrets,
                inbox=slot / "inbox",
                power_file=power,
                session_file=session,
                network_file=network,
                local_remote=slot / "bare.git",
            ),
            verifier=valid,
            operator_id="operator",
            reviewer_id="reviewer",
            allowed_command=(sys.executable, str(_ok_script(tmp_path))),
            command_cwd="src",
        )
        posted._post_handoff(
            9,
            "https://github.com/cwall5640/fixture/pull/9",
            sha,
            during,
            "PASS",
        )
    finally:
        api.stop()
    assert any("INTERIM UNTIL: 2026-11-11" in body for body in api.bodies)
    assert any("SIGNED BY: synthetic-interim (Synthetic Interim)" in body for body in api.bodies)
    api = FixtureApi(sha)
    api.labels = []
    api.has_pull = True
    api.pr_sha = "b" * 40
    api.pr_sha_next = "b" * 40
    api.comments = [{"body": _signed_next(VIBE_SECRET, "b" * 40)}]
    try:
        matched = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="pr-head")
        with pytest.raises(Disabled, match="publisher is disabled"):
            matched.run_once()
    finally:
        api.stop()
    assert (tmp_path / "pr-head" / "workspace").is_dir()
    api = FixtureApi(sha)
    api.labels = []
    api.pr_sha = "b" * 40
    api.pr_sha_next = "b" * 40
    api.comments = [{"body": _signed_next(VIBE_SECRET, sha)}]
    try:
        stale = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="pr-base")
        assert stale.run_once()["status"] == "stale_head"
    finally:
        api.stop()
    assert not (tmp_path / "pr-base" / "workspace").exists()
    api = FixtureApi(sha)
    api.labels = []
    api.has_pull = False
    api.comments = [{"body": _signed_next(VIBE_SECRET, sha)}]
    try:
        issue = _candidate(tmp_path, api, sha, _script(tmp_path, fail_until=1), name="issue-base")
        with pytest.raises(Disabled, match="publisher is disabled"):
            issue.run_once()
    finally:
        api.stop()


def _assert_windows_reparse_secret(tmp_path: Path) -> None:
    """Symlink creation needs SeCreateSymbolicLink. A junction does not."""

    real = tmp_path / "reparse-real"
    secret = real / "values"
    write_secret_file(
        secret,
        {
            "github_read": "read-token",
            "github_ci": "ci-token",
            "github_publish": PUBLISH,
            "grant_key": "grant-key",
            "proxy_auth": "proxy-token",
        },
    )
    link = tmp_path / "reparse-link"
    try:
        link.symlink_to(secret)
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror not in {1314, 5}:
            raise
        junction = tmp_path / "reparse-junction"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(real)],
            check=True,
            capture_output=True,
        )
        with pytest.raises(Forbidden, match="reparse"):
            load_secret_file(junction / "values")
        return
    with pytest.raises(Forbidden):
        load_secret_file(link)


def test_binary_integrity_key_preserves_every_byte(tmp_path: Path) -> None:
    from free_claude_code.assignments.workflow import _io_flags

    path = tmp_path / "integrity.key"
    payload = bytes(range(256))
    fd = os.open(path, _io_flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL), 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    assert path.read_bytes() == payload


def test_windows_pid_query_does_not_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    from free_claude_code.assignments.windows_acl import process_is_running
    from free_claude_code.assignments.workflow import _pid_alive

    assert process_is_running(True, 259) is True
    assert process_is_running(True, 0) is False
    assert process_is_running(False, 259) is False
    seen: list[int] = []

    def query(pid: int) -> bool:
        seen.append(pid)
        return False

    def explode(*_args: object) -> None:
        raise AssertionError("os.kill must not be used to probe a Windows process")

    monkeypatch.setattr("free_claude_code.assignments.workflow._platform_name", lambda: "nt")
    monkeypatch.setattr("free_claude_code.assignments.windows_acl.windows_pid_alive", query)
    monkeypatch.setattr(os, "kill", explode)
    assert _pid_alive(4242) is False
    assert seen == [4242]


def test_startup_install_is_disabled_and_package_is_real() -> None:
    assert cli_main(["show-contract"]) == 0
    assert cli_main(["activate"]) == 2
    assert candidate_main(["run-once"]) == 2
    assert CAPABILITY_BOUNDARY["manager_signatures"] == "ed25519_public_key_only"
    assert CAPABILITY_BOUNDARY["text_signature"] == "convention_only_not_authority"
    assert CAPABILITY_BOUNDARY["manager_set"] == "config_file_of_pinned_public_keys"
    assert CAPABILITY_BOUNDARY["manager_attestation"] == "one_signature_covers_execute_and_publish"
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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DACL runs on Windows")
def test_windows_dacl_native(tmp_path: Path) -> None:
    from free_claude_code.assignments.windows_acl import file_is_current_user_only

    path = tmp_path / "secrets" / "values"
    write_secret_file(
        path,
        {
            "github_read": "read-token",
            "github_ci": "ci-token",
            "github_publish": PUBLISH,
            "grant_key": "grant-key",
            "proxy_auth": "proxy-token",
        },
    )
    assert file_is_current_user_only(path)
    assert file_is_current_user_only(path.parent)
    loose = tmp_path / "loose"
    loose.mkdir()
    insecure = loose / "values"
    insecure.write_text("github_read=read-token\n", encoding="utf-8")
    with pytest.raises(Forbidden):
        load_secret_file(insecure)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions run on Windows")
def test_windows_reparse_native(tmp_path: Path) -> None:
    _assert_windows_reparse_secret(tmp_path)


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell ShowContract runs on Windows")
def test_windows_powershell_show_contract(tmp_path: Path) -> None:
    script = Path("packaging/assignment-candidate/windows/Invoke-AssignmentCandidate.ps1")
    root = tmp_path / "scratch"
    root.mkdir()
    missing = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-Mode",
            "ShowContract",
            "-Root",
            str(root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode == 2
    loaded = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-Mode",
            "ShowContract",
            "-Root",
            str(root),
            "-Python",
            sys.executable,
            "-SourceRoot",
            str(Path("src").resolve()),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert loaded.returncode == 0
    assert "activation" in loaded.stdout
    assert "disabled" in loaded.stdout
