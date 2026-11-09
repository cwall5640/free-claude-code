# SPDX-License-Identifier: AGPL-3.0-only
"""Logon task XML and AC-only wake. Linux uses fakes. Windows registration is skipped."""

import json
import sys
from pathlib import Path

import pytest

from free_claude_code.assignments.candidate import main as candidate_main
from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.startup_task import (
    TASK_NAME,
    build_logon_task_xml,
    install_layout,
    register_logon_task,
    unregister_logon_task,
)
from free_claude_code.assignments.wake import (
    ES_DISPLAY_REQUIRED,
    PluggedInWake,
    clear_flags,
    hold_flags,
)

PYTHON = Path(r"C:\Users\alice\claude1-assignment-venv\Scripts\python.exe")
STATE = Path(r"C:\Users\alice\claude1-assignment-candidate\state")
CONFIG = Path(r"C:\Users\alice\claude1-worker-config")
USER = r"MACHINE\alice"
SID = "S-1-5-21-100"


def _xml() -> str:
    return build_logon_task_xml(user=USER, user_sid=SID, python=PYTHON, state=STATE, config=CONFIG)


def test_logon_task_is_per_user_least_privilege() -> None:
    xml = _xml()
    assert "LeastPrivilege" in xml
    assert "InteractiveToken" in xml
    assert "LogonTrigger" in xml
    assert USER in xml
    assert SID in xml
    assert "HighestAvailable" not in xml
    assert "S-1-5-18" not in xml
    assert "Password" not in xml
    assert "S4U" not in xml
    assert "powercfg" not in xml.casefold()
    assert "free_claude_code.assignments.candidate logon" in xml
    assert "xoxb-" not in xml
    assert "github_publish" not in xml
    layout = install_layout(Path(r"C:\Users\alice"))
    assert layout["install"].name == "claude1-assignment-candidate"
    assert layout["venv"].name == "claude1-assignment-venv"
    assert layout["venv"].parent == layout["install"].parent
    assert layout["python"] == layout["venv"] / "Scripts" / "python.exe"
    assert layout["config"].name == "claude1-worker-config"
    assert layout["state"].name == "state"


def test_register_and_unregister_use_only_the_fixed_name() -> None:
    xml = _xml()
    created: list[str] = []
    register_logon_task(xml, task_name=TASK_NAME, create=lambda name, _xml: created.append(name))
    register_logon_task(xml, task_name=TASK_NAME, create=lambda name, _xml: created.append(name))
    assert created == [TASK_NAME, TASK_NAME]
    with pytest.raises(Forbidden):
        register_logon_task(xml, task_name="Inkbound", create=lambda name, _xml: created.append(name))
    deleted: list[str] = []
    unregister_logon_task(task_name=TASK_NAME, delete=deleted.append)
    assert deleted == [TASK_NAME]
    with pytest.raises(Forbidden):
        unregister_logon_task(task_name="claude1-assignment-worker-extra", delete=deleted.append)
    assert deleted == [TASK_NAME]


def test_system_and_preserved_paths_are_refused() -> None:
    with pytest.raises(Forbidden):
        build_logon_task_xml(
            user=r"NT AUTHORITY\SYSTEM",
            user_sid="S-1-5-18",
            python=PYTHON,
            state=STATE,
            config=CONFIG,
        )
    with pytest.raises(Forbidden):
        build_logon_task_xml(
            user=USER,
            user_sid=SID,
            python=Path(r"C:\Users\alice\AppData\Local\Programs\FreeClaudeCode\python.exe"),
            state=STATE,
            config=CONFIG,
        )


def test_logon_stays_disabled_and_does_not_read_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("secret file was read")

    monkeypatch.setattr("free_claude_code.assignments.secrets.load_secret_file", boom)
    config = tmp_path / "config"
    config.mkdir()
    secret = config / "secrets"
    secret.write_text("github_publish=not-a-real-token\n", encoding="utf-8")
    calls: list[bool] = []

    def fake_proxy(*, enabled: bool, launcher: Path, **_kwargs: object) -> str:
        calls.append(enabled)
        return "healthy"

    monkeypatch.setattr("free_claude_code.assignments.live.ensure_fcc_proxy", fake_proxy)
    state = tmp_path / "state"
    assert candidate_main(["logon", "--root", str(state), "--config", str(config)]) == 0
    assert "logon idle" in (state / "logon.log").read_text(encoding="utf-8")
    assert calls == []
    assert secret.read_text(encoding="utf-8").startswith("github_publish=")
    (state / "enabled").write_text("true\n", encoding="utf-8")
    assert candidate_main(["logon", "--root", str(state), "--config", str(config)]) == 0
    assert calls == []
    assert "logon idle" in (state / "logon.log").read_text(encoding="utf-8")


def test_wake_sets_on_ac_and_does_nothing_on_battery_or_posix() -> None:
    assert hold_flags() & ES_DISPLAY_REQUIRED == 0
    assert clear_flags() == 0x80000000
    calls: list[int] = []
    power = {"value": "ac"}
    wake = PluggedInWake(ac_status=lambda: power["value"], set_state=calls.append, platform="nt", interval=60)
    wake.tick()
    assert calls == [hold_flags()]
    power["value"] = "battery"
    wake.tick()
    assert calls == [hold_flags(), clear_flags()]
    calls.clear()
    wake2 = PluggedInWake(ac_status=lambda: "battery", set_state=calls.append, platform="nt")
    wake2.tick()
    assert calls == []
    calls.clear()
    with PluggedInWake(ac_status=lambda: "ac", set_state=calls.append, platform="posix"):
        pass
    assert calls == []


def test_launcher_records_the_task_and_leaves_install_disabled() -> None:
    script = Path("packaging/assignment-candidate/windows/Invoke-AssignmentCandidate.ps1").read_text(encoding="utf-8")
    assert "\r" not in script
    assert "RegisterStartup" in script
    assert "UnregisterStartup" in script
    assert "claude1-assignment-worker" in script
    assert "Join-Path $profile 'claude1-assignment-venv'" in script
    assert "venv python is missing" in script
    assert "schtasks.exe /Create /TN $TaskName /XML $xmlPath /F" in script
    assert "schtasks.exe /Delete /TN $TaskName /F" in script
    assert "HIGHEST" not in script
    assert "powercfg" not in script.casefold()
    plan = json.loads(Path("packaging/assignment-candidate/activation-rollback.json").read_text(encoding="utf-8"))
    assert plan["executed"] is False
    assert plan["activation_enabled"] is False
    assert plan["logon_task_name"] == TASK_NAME
    assert "UnregisterStartup" in plan["unregister_startup"]
    assert "RegisterStartup" in plan["register_startup"]


@pytest.mark.skipif(sys.platform != "win32", reason="execution state runs on Windows")
def test_windows_wake_clears_without_touching_the_power_plan() -> None:
    from free_claude_code.assignments.wake import windows_set_execution_state

    try:
        windows_set_execution_state(hold_flags())
    finally:
        windows_set_execution_state(clear_flags())
    assert hold_flags() & ES_DISPLAY_REQUIRED == 0
