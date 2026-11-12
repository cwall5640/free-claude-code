import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from free_claude_code.assignments import live
from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.execution import is_playwright_test_command
from free_claude_code.assignments.secrets import SecretFile

# EXEC-RETRY-01 repair (Cody HOLD on PR #36; Producer decision, Casey,
# 2026-11-11): the failed-test re-run inside the check stage is authorized
# only by the explicit runtime opt-in allow_failed_test_rerun — absent or
# false by default — and the opt-in is refused at this configuration
# boundary for any configured command that is not a Playwright test
# invocation, so a non-Playwright check can never receive --last-failed.

PLAYWRIGHT_COMMAND = ["npx.cmd", "playwright", "test", "--reporter=list", "--workers=1"]


def _config(tmp_path: Path, **extra: object) -> Path:
    raw = {
        "allowed_command": PLAYWRIGHT_COMMAND,
        "owner": "owner",
        "repo": "game",
        "operator_id": "operator",
        "reviewer_id": "reviewer",
        "audience": "worker",
        "source_repo": str(tmp_path),
        **extra,
    }
    (tmp_path / "runtime.json").write_text(json.dumps(raw), encoding="utf-8")
    return tmp_path


def test_rerun_opt_in_defaults_off(tmp_path):
    assert live._runtime(_config(tmp_path))["allow_failed_test_rerun"] is False


def test_rerun_opt_in_accepted_for_a_playwright_command(tmp_path):
    runtime = live._runtime(_config(tmp_path, allow_failed_test_rerun=True))
    assert runtime["allow_failed_test_rerun"] is True


@pytest.mark.parametrize(
    "command",
    [
        ["python", "check.py"],
        ["pytest", "-q"],
        ["make", "test"],
        ["npx.cmd", "playwright", "install"],
        ["npx.cmd", "playwright"],
    ],
)
def test_rerun_opt_in_refused_for_a_non_playwright_command(tmp_path, command):
    with pytest.raises(Forbidden):
        live._runtime(_config(tmp_path, allowed_command=command, allow_failed_test_rerun=True))


@pytest.mark.parametrize("value", ["yes", 1, 0, None, [True], {}])
def test_rerun_opt_in_must_be_a_boolean(tmp_path, value):
    with pytest.raises(Forbidden):
        live._runtime(_config(tmp_path, allow_failed_test_rerun=value))


def _candidate_kwargs(tmp_path, monkeypatch, config):
    monkeypatch.setattr(live, "load_worker_identity", lambda *_: SimpleNamespace(enabled=True))
    monkeypatch.setattr(live, "load_manager_config", lambda *_: [SimpleNamespace(principal_id="manager")])
    monkeypatch.setattr(live, "load_secret_file", lambda *_: SecretFile({"github_read": "test"}))
    monkeypatch.setattr(live, "GitHubHttpClient", lambda *args, **kwargs: None)
    monkeypatch.setattr(live, "_verifier", lambda *args: None)
    monkeypatch.setattr(live, "AssignmentCandidate", lambda **kwargs: SimpleNamespace(**kwargs))
    return live._candidate(tmp_path / "state", config, live._runtime(config))


def test_rerun_opt_in_reaches_candidate(tmp_path, monkeypatch):
    config = _config(tmp_path, allow_failed_test_rerun=True)
    candidate = _candidate_kwargs(tmp_path, monkeypatch, config)
    assert candidate.allow_failed_test_rerun is True


def test_rerun_opt_in_reaches_candidate_off_by_default(tmp_path, monkeypatch):
    candidate = _candidate_kwargs(tmp_path, monkeypatch, _config(tmp_path))
    assert candidate.allow_failed_test_rerun is False


@pytest.mark.parametrize(
    "command",
    [
        ("npx.cmd", "playwright", "test", "--reporter=list", "--workers=1"),
        ("npx", "playwright", "test"),
        ("playwright", "test"),
        ("playwright.cmd", "test", "tests/"),
    ],
)
def test_playwright_shape_is_recognized(command):
    assert is_playwright_test_command(command) is True


@pytest.mark.parametrize(
    "command",
    [
        ("python", "check.py"),
        ("pytest", "-q"),
        ("make", "test"),
        ("npx.cmd", "playwright", "install"),
        ("npx.cmd", "test"),
        ("playwright",),
        (),
    ],
)
def test_non_playwright_shape_is_not_recognized(command):
    assert is_playwright_test_command(command) is False
