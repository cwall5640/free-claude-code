# SPDX-License-Identifier: AGPL-3.0-only
"""Gated local checkout, commands, CI reads, and merge-free publication.

Issue text is data. It cannot approve a command, widen a path, or mint a
GitHub credential. Publication tokens stay on the publisher object and are
not copied into command environments. Merge is not implemented.
"""

import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from free_claude_code.assignments.errors import (
    ApprovalInvalid,
    Cancelled,
    Conflict,
    Forbidden,
    MergeRejected,
    ScopeError,
    TimedOut,
)
from free_claude_code.assignments.models import PublicationPlan, TaskManifest
from free_claude_code.assignments.paths import contained, is_forbidden_repo_path, path_allowed
from free_claude_code.assignments.redact import redact
from free_claude_code.assignments.service import CancellationToken

_SECRET_ENV = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NVIDIA_NIM_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "GH_ENTERPRISE_TOKEN",
)
_NEVER_COMMANDS = frozenset(
    {"gh", "git", "bash", "sh", "pwsh", "powershell", "cmd", "curl", "wget", "ssh"}
)
_GIT_FORBIDDEN = frozenset(
    {"merge", "push", "pull", "rebase", "reset", "clean", "filter-branch", "update-ref"}
)
_MERGE_TEXT = (
    "gh pr merge",
    "gh api",
    "--auto",
    "automerge",
    "auto-merge",
    "pull_request_target",
)


@dataclass(frozen=True, slots=True)
class NativeCommandApproval:
    """Exact argv approval. Issue comments cannot construct this."""

    manifest_id: str
    argv: tuple[str, ...]
    operator_id: str


@dataclass(frozen=True, slots=True)
class CommandEvidence:
    argv: tuple[str, ...]
    cwd: str
    returncode: int | None
    python_version: str
    head_sha: str
    manifest_id: str
    stdout_tail: str
    stderr_tail: str
    timed_out: bool
    cancelled: bool
    passed: int
    failed: int
    skipped: int
    flaky: int
    browser: str

    @property
    def local_outcome(self) -> str:
        if self.cancelled or self.timed_out or self.returncode is None:
            return "INCOMPLETE"
        if self.failed or self.returncode != 0:
            return "HOLD"
        if self.passed and not self.failed:
            return "PASS"
        return "INCOMPLETE"


@dataclass(frozen=True, slots=True)
class CiCheck:
    name: str
    status: str
    conclusion: str | None
    head_sha: str
    duration_seconds: float
    log_excerpt: str


@dataclass(frozen=True, slots=True)
class CiObservation:
    """A read of check status. This is not a test run and not a rerun."""

    head_sha: str
    checks: tuple[CiCheck, ...]
    awaiting_prs: int
    slowest_check_seconds: float
    config_blocker_seconds: float
    checks_observable: bool

    def admit_heavy_work(self) -> str:
        if not self.checks_observable:
            return "pause"
        if self.awaiting_prs > 8:
            return "pause"
        if self.slowest_check_seconds > 12 * 60:
            return "pause"
        if self.config_blocker_seconds > 24 * 60:
            return "pause"
        return "admit"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Separate local tests from CI. PASS is not merge or model approval."""

    overall: str
    local_tests: str
    ci: str
    limitations: tuple[str, ...]
    next_steps: tuple[str, ...]
    merge_allowed: bool = False
    model_invoked: bool = False

    def __post_init__(self) -> None:
        if self.merge_allowed or self.model_invoked:
            raise Forbidden("a verdict cannot grant merge or claim a model call")
        if self.overall not in {"PASS", "HOLD", "INCOMPLETE"}:
            raise Forbidden("unknown verdict")


def commands_from_issue(_body: str) -> tuple[str, ...]:
    """Issue text is data. It cannot become a command line."""

    raise Forbidden("issue text cannot supply commands")


def vet_command(argv: Sequence[str], allowed: Sequence[Sequence[str]]) -> tuple[str, ...]:
    frozen = tuple(argv)
    if not frozen or any("\x00" in part or part == "" for part in frozen):
        raise Forbidden("empty command")
    base = Path(frozen[0]).name.lower()
    if base in _NEVER_COMMANDS or base.endswith(".exe") and base[:-4] in _NEVER_COMMANDS:
        raise Forbidden(f"command {base} is not available to the sandbox")
    joined = " ".join(frozen).lower()
    if any(token in joined for token in _MERGE_TEXT):
        raise MergeRejected("command text includes a merge or privileged API")
    if not any(tuple(prefix) == frozen[: len(prefix)] for prefix in allowed if prefix):
        raise Forbidden("command is not on the exact allowlist")
    return frozen


def scrub_env(source: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in source.items() if key not in _SECRET_ENV}


def parse_unittest(output: str) -> tuple[int, int, int, int]:
    """Best-effort unittest counts. Unparsed output is not a pass."""

    passed = failed = skipped = flaky = 0
    ran = 0
    for line in output.splitlines():
        if line.startswith("Ran ") and " test" in line:
            ran = int(line.split()[1])
        if line.startswith("OK"):
            skipped += line.count("skipped=") and int(line.split("skipped=")[1].split(")")[0])
        if "FAILED" in line or "errors=" in line:
            failed += _count_field(line, "failures") + _count_field(line, "errors")
        if "skipped=" in line and "OK" not in line:
            skipped += _count_field(line, "skipped")
    if ran and failed == 0 and output.strip().splitlines()[-1:] == ["OK"] or (
        ran and failed == 0 and any(line.startswith("OK") for line in output.splitlines())
    ):
        passed = max(ran - skipped, 0)
    elif ran and failed:
        passed = max(ran - failed - skipped, 0)
    return passed, failed, skipped, flaky


def _count_field(line: str, name: str) -> int:
    token = f"{name}="
    if token not in line:
        return 0
    raw = line.split(token, 1)[1]
    digits = []
    for char in raw:
        if char.isdigit():
            digits.append(char)
        else:
            break
    return int("".join(digits) or "0")


class GitWorkspace:
    """Fixed git operations. There is no merge or push method."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def materialize(self, source: Path, sha: str, branch: str) -> str:
        if branch in {"main", "master"} or ".." in branch.split("/"):
            raise Forbidden("refusing protected or unsafe branch name")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._run(("clone", "--local", str(source), str(self.path)), cwd=self.path.parent)
        self._run(("checkout", "--detach", sha), cwd=self.path)
        self._run(("switch", "-c", branch), cwd=self.path)
        head = self.head()
        if head != sha:
            raise Forbidden("checkout did not land on the approved SHA")
        if not self.ancestry_contains(sha, head):
            raise Forbidden("HEAD is not the approved commit")
        return head

    def head(self) -> str:
        return self._run(("rev-parse", "HEAD"), cwd=self.path).strip()

    def ancestry_contains(self, ancestor: str, descendant: str) -> bool:
        result = self._run(
            ("merge-base", "--is-ancestor", ancestor, descendant),
            cwd=self.path,
            check=False,
        )
        return result == ""

    def diff(self) -> str:
        return self._run(("diff", "HEAD"), cwd=self.path)

    def commit_scoped(self, paths: tuple[str, ...], message: str) -> str:
        if not paths:
            raise ScopeError("commit requires explicit paths")
        safe = tuple(path_ok(path) for path in paths)
        self._run(("add", "--", *safe), cwd=self.path)
        self._run(("commit", "-m", message, "--", *safe), cwd=self.path)
        return self.head()

    def _run(self, args: tuple[str, ...], *, cwd: Path, check: bool = True) -> str:
        if not args or args[0] in _GIT_FORBIDDEN:
            raise MergeRejected("git subcommand is not available")
        if any(flag in args for flag in ("--force", "--force-with-lease", "-f")):
            raise MergeRejected("force git operations are not available")
        env = scrub_env(os.environ)
        env.update(
            {
                "GIT_AUTHOR_NAME": "fcc-assignment",
                "GIT_AUTHOR_EMAIL": "fcc-assignment@localhost",
                "GIT_COMMITTER_NAME": "fcc-assignment",
                "GIT_COMMITTER_EMAIL": "fcc-assignment@localhost",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            }
        )
        completed = subprocess.run(
            ("git", *args),
            cwd=cwd,
            env=env,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and completed.returncode != 0:
            detail = redact(completed.stderr.strip() or completed.stdout.strip())
            raise Forbidden(f"git {args[0]} failed: {detail}")
        if args[:2] == ("merge-base", "--is-ancestor"):
            return "" if completed.returncode == 0 else "no"
        return completed.stdout.strip()


def path_ok(relative: str) -> str:
    from free_claude_code.assignments.paths import safe_relative

    safe = safe_relative(relative)
    if is_forbidden_repo_path(safe):
        raise ScopeError("path is forbidden")
    return safe


class Sandbox:
    """Runs exact allowlisted argv values. shell=True is not used."""

    def __init__(
        self,
        root: Path,
        *,
        allowed: Sequence[Sequence[str]],
        timeout_seconds: float = 30.0,
    ) -> None:
        self.root = root
        self.allowed = tuple(tuple(item) for item in allowed)
        self.timeout_seconds = timeout_seconds
        self.evidence: list[CommandEvidence] = []

    def run(
        self,
        approval: NativeCommandApproval,
        *,
        manifest: TaskManifest,
        head_sha: str,
        cancellation: CancellationToken | None = None,
    ) -> CommandEvidence:
        if approval.manifest_id != manifest.manifest_id:
            raise ApprovalInvalid("command approval is for a different task")
        if approval.operator_id.strip() == "":
            raise Forbidden("command approval needs a local operator")
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        argv = vet_command(approval.argv, self.allowed)
        env = scrub_env(os.environ)
        started = time.monotonic()
        timed_out = False
        cancelled = False
        returncode: int | None = None
        stdout = stderr = ""
        process = subprocess.Popen(
            argv,
            cwd=self.root,
            env=env,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = started + self.timeout_seconds
        while process.poll() is None:
            if token._cancelled:
                process.kill()
                cancelled = True
                break
            if time.monotonic() >= deadline:
                process.kill()
                timed_out = True
                break
            time.sleep(0.02)
        out, err = process.communicate()
        stdout = redact(out or "")
        stderr = redact(err or "")
        if not timed_out and not cancelled:
            returncode = process.returncode
        passed, failed, skipped, flaky = parse_unittest(stdout + "\n" + stderr)
        evidence = CommandEvidence(
            argv=argv,
            cwd=str(self.root),
            returncode=returncode,
            python_version=sys.version.split()[0],
            head_sha=head_sha,
            manifest_id=manifest.manifest_id,
            stdout_tail=stdout[-2000:],
            stderr_tail=stderr[-2000:],
            timed_out=timed_out,
            cancelled=cancelled,
            passed=passed,
            failed=failed,
            skipped=skipped,
            flaky=flaky,
            browser="not_checked",
        )
        self.evidence.append(evidence)
        if timed_out:
            raise TimedOut("command exceeded its timeout")
        if cancelled:
            raise Cancelled("command was cancelled")
        return evidence


class CiReader:
    """Read-only check view. It does not execute tests or rerun jobs."""

    def __init__(self, checks: tuple[CiCheck, ...], *, awaiting_prs: int = 0, blocker_seconds: float = 0.0) -> None:
        self._checks = checks
        self.awaiting_prs = awaiting_prs
        self.blocker_seconds = blocker_seconds
        self.reads = 0
        self.reruns = 0

    def observe(self, head_sha: str) -> CiObservation:
        self.reads += 1
        matched = tuple(check for check in self._checks if check.head_sha == head_sha)
        slowest = max((check.duration_seconds for check in matched), default=0.0)
        return CiObservation(
            head_sha=head_sha,
            checks=matched,
            awaiting_prs=self.awaiting_prs,
            slowest_check_seconds=slowest,
            config_blocker_seconds=self.blocker_seconds,
            checks_observable=bool(matched),
        )


class CiRerunner:
    """Separate from reading and from local tests. Still cannot merge."""

    def __init__(self, reader: CiReader) -> None:
        self.reader = reader
        self.requested: list[str] = []

    def rerun(self, observation: CiObservation, name: str, *, approved: bool) -> None:
        if not approved:
            raise ApprovalInvalid("CI rerun requires its own approval")
        if observation.admit_heavy_work() != "admit":
            raise Forbidden("heavy CI is paused until checks are observable and short")
        if name not in {check.name for check in observation.checks}:
            raise Forbidden("CI job is not in the observed set")
        self.reader.reruns += 1
        self.requested.append(name)


class TokenVault:
    """Holds a publication secret away from command environments."""

    def __init__(self, token: str) -> None:
        self._token = token

    def __repr__(self) -> str:
        return "TokenVault([redacted])"

    def header(self) -> str:
        return f"Bearer {self._token}"


class NarrowPublisher:
    """Open a review pull request. Merge methods always raise."""

    def __init__(self, vault: TokenVault | None = None) -> None:
        self._vault = vault
        self.opened: list[PublicationPlan] = []

    def open_review_pr(self, plan: PublicationPlan) -> str:
        if plan.auto_merge or plan.direct_push:
            raise MergeRejected("publication cannot merge or push the default branch")
        if self._vault is None:
            raise Forbidden("publication credentials are not configured")
        _ = self._vault.header()
        self.opened.append(plan)
        return f"https://github.example/{plan.head_branch}"

    def merge(self, *_args: object, **_kwargs: object) -> None:
        raise MergeRejected("merge API is not available to the worker")

    def enable_auto_merge(self, *_args: object, **_kwargs: object) -> None:
        raise MergeRejected("auto-merge cannot be enabled")

    def push_default_branch(self, branch: str) -> None:
        raise MergeRejected(f"refusing to push {branch}")


class NvidiaClaudeLauncher:
    """Builds a fixed Claude argv. It does not spawn without a model grant.

    The grant is a local operator object, not issue text. The launcher never
    receives the publication vault.
    """

    def __init__(self) -> None:
        self.spawned = False
        self.last_env: dict[str, str] | None = None

    def run(
        self,
        manifest: TaskManifest,
        workspace: Path,
        *,
        grant_manifest_id: str | None,
        grant_repo: str | None,
        spawn: Callable[..., object] | None = None,
    ) -> None:
        if grant_manifest_id != manifest.manifest_id or grant_repo != f"{manifest.owner}/{manifest.repo}":
            raise Forbidden("NVIDIA session is outside the approved repo boundary")
        argv = ("claude", "--print")
        env = scrub_env(os.environ)
        env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:8082"
        self.last_env = env
        if spawn is None:
            raise Forbidden("NVIDIA process spawn is not authorized in this process")
        contained(workspace, workspace)
        spawn(argv, env)
        self.spawned = True


def apply_scoped_write(
    workspace: Path,
    manifest: TaskManifest,
    relative: str,
    content: str,
) -> None:
    if not path_allowed(relative, manifest.scope.allowed_prefixes):
        raise ScopeError("write is outside the approved scope")
    target = contained(workspace, workspace / relative)
    if any(token in content.lower() for token in _MERGE_TEXT):
        raise MergeRejected("file content includes a merge instruction")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def build_verdict(
    local: CommandEvidence | None,
    ci: CiObservation | None,
    *,
    model_invoked: bool = False,
) -> Verdict:
    limitations = [
        "PASS is local evidence only and is not merge approval.",
        "The worker has no merge API.",
        "NVIDIA Claude Code was not invoked." if not model_invoked else "model flag was set",
        "Browser availability was not checked.",
    ]
    next_steps = ["Independent reviewer opens or accepts the review pull request."]
    if local is None:
        return Verdict(
            "INCOMPLETE",
            "INCOMPLETE",
            "not_read",
            tuple(limitations),
            ("Run the approved local test command.",),
        )
    local_outcome = local.local_outcome
    if ci is None:
        limitations.append("CI status was not read.")
        overall = "HOLD" if local_outcome == "PASS" else local_outcome
        return Verdict(overall, local_outcome, "not_read", tuple(limitations), tuple(next_steps))
    if ci.admit_heavy_work() != "admit":
        limitations.append("Heavy CI is paused by queue, duration, or missing checks.")
        return Verdict("HOLD", local_outcome, "paused", tuple(limitations), ("Wait for observable checks.",))
    failed = [check.name for check in ci.checks if check.conclusion not in {None, "success", "skipped"}]
    ci_state = "PASS" if ci.checks and not failed else "HOLD"
    overall = "PASS" if local_outcome == "PASS" and ci_state == "PASS" else "HOLD"
    if overall == "PASS":
        limitations.append("Overall PASS still does not authorize merge.")
    return Verdict(overall, local_outcome, ci_state, tuple(limitations), tuple(next_steps))


def claim_writer(active: dict[str, str], task_key: str, operator_id: str) -> None:
    current = active.get(task_key)
    if current is not None and current != operator_id:
        raise Conflict("another writer holds this assignment")
    active[task_key] = operator_id
