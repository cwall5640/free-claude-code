# SPDX-License-Identifier: AGPL-3.0-only
"""Proxy startup is mocked. A disabled worker does not probe or spawn."""

from pathlib import Path

import pytest

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.fcc_proxy import (
    HEALTH_URL,
    default_fcc_launcher,
    ensure_fcc_proxy,
    resolve_fcc_launcher,
)
from free_claude_code.assignments.identity import load_worker_identity


def test_default_launcher_is_the_original_install() -> None:
    launcher = default_fcc_launcher(Path(r"C:\Users\alice"))
    assert launcher.name == "start-windows.ps1"
    assert launcher.parts[-2] == "FreeClaudeCode"
    assert resolve_fcc_launcher(Path(r"C:\Users\alice"), "") == launcher
    custom = Path(r"C:\Users\alice\AppData\Local\Programs\FreeClaudeCode\start-windows.ps1")
    assert resolve_fcc_launcher(Path(r"C:\Users\alice"), str(custom)) == custom
    with pytest.raises(Forbidden):
        resolve_fcc_launcher(Path(r"C:\Users\alice"), "start-windows.ps1")
    loaded = load_worker_identity(Path("packaging/assignment-candidate/worker.example.json"))
    assert loaded.fcc_launcher == ""


def test_disabled_worker_does_not_touch_the_proxy(tmp_path: Path) -> None:
    def probe(_url: str) -> int:
        raise AssertionError("health was probed")

    def spawn(_argv: list[str], _env: dict[str, str]) -> None:
        raise AssertionError("fcc was started")

    assert (
        ensure_fcc_proxy(
            enabled=False,
            launcher=tmp_path / "start-windows.ps1",
            probe=probe,
            spawn=spawn,
        )
        == "disabled"
    )


def test_enabled_worker_starts_original_fcc_without_secrets(tmp_path: Path) -> None:
    launcher = tmp_path / "FreeClaudeCode" / "start-windows.ps1"
    launcher.parent.mkdir()
    launcher.write_text("# existing launcher\n", encoding="utf-8")
    seen: dict[str, object] = {}
    statuses = iter([0, 200])

    def probe(url: str) -> int:
        assert url == HEALTH_URL
        return next(statuses)

    def spawn(argv: list[str], env: dict[str, str]) -> None:
        seen["argv"] = argv
        seen["env"] = env

    result = ensure_fcc_proxy(
        enabled=True,
        launcher=launcher,
        probe=probe,
        spawn=spawn,
        environ={
            "PATH": r"C:\Windows",
            "USERPROFILE": r"C:\Users\alice",
            "GITHUB_TOKEN": "ghp_not-real",
            "SLACK_BOT_TOKEN": "xoxb-not-real",
            "PYTHONPATH": r"C:\Users\alice\claude1-assignment-candidate\src",
        },
    )
    assert result == "started"
    assert seen["argv"] == [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(launcher),
    ]
    env = seen["env"]
    assert isinstance(env, dict)
    assert env["PATH"] == r"C:\Windows"
    assert "GITHUB_TOKEN" not in env
    assert "SLACK_BOT_TOKEN" not in env
    assert "PYTHONPATH" not in env
    assert "ghp_not-real" not in " ".join(seen["argv"])
    assert "xoxb-not-real" not in " ".join(seen["argv"])


def test_healthy_proxy_is_not_restarted_and_a_dead_proxy_skips(tmp_path: Path) -> None:
    launcher = tmp_path / "start-windows.ps1"
    launcher.write_text("# existing\n", encoding="utf-8")

    def spawn(_argv: list[str], _env: dict[str, str]) -> None:
        raise AssertionError("healthy proxy was restarted")

    assert ensure_fcc_proxy(enabled=True, launcher=launcher, probe=lambda _url: 200, spawn=spawn) == "healthy"
    clock = {"now": 0.0}

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    assert (
        ensure_fcc_proxy(
            enabled=True,
            launcher=tmp_path / "missing.ps1",
            probe=lambda _url: 0,
            spawn=spawn,
            now=lambda: clock["now"],
            sleep=sleep,
            wait_seconds=1.0,
        )
        == "down"
    )
