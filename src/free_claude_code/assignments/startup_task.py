# SPDX-License-Identifier: AGPL-3.0-only
"""Per-user logon task for claude1. Install does not register it.

The task runs as the current user, at logon, with LeastPrivilege. It does not
run as SYSTEM and it does not run when the user is logged off. The command
line carries paths only. While this build is disabled, logon writes a log
line and exits without reading secrets or calling GitHub or Slack.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.private_io import append_private_bytes, ensure_private_dir

TASK_NAME = "claude1-assignment-worker"
_FORBIDDEN_USERS = frozenset(
    {
        "system",
        "nt authority\\system",
        "local service",
        "nt authority\\local service",
        "network service",
        "nt authority\\network service",
    }
)
_FORBIDDEN_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})


def install_layout(profile: Path) -> dict[str, Path]:
    """Paths for one Windows user. The profile is the only account-specific part."""

    install = profile / "claude1-assignment-candidate"
    return {
        "install": install,
        "python": install / "claude1-assignment-venv" / "Scripts" / "python.exe",
        "state": install / "state",
        "config": profile / "claude1-worker-config",
    }


def build_logon_task_xml(
    *,
    user: str,
    user_sid: str,
    python: Path,
    state: Path,
    config: Path,
) -> str:
    """Task XML: current user, interactive logon, least privilege."""

    account = _require_current_user(user)
    sid = _require_user_sid(user_sid)
    command = _require_path(python)
    state_path = _require_path(state)
    config_path = _require_path(config)
    arguments = (
        "-m free_claude_code.assignments.candidate logon "
        f'--root "{state_path}" --config "{config_path}"'
    )
    _refuse_secret_text(command, arguments, str(Path(state_path).parent))
    working = escape(str(Path(state_path).parent))
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <Principals>\n"
        '    <Principal id="Author">\n'
        f"      <UserId>{escape(sid)}</UserId>\n"
        "      <LogonType>InteractiveToken</LogonType>\n"
        "      <RunLevel>LeastPrivilege</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Triggers>\n"
        "    <LogonTrigger>\n"
        "      <Enabled>true</Enabled>\n"
        f"      <UserId>{escape(account)}</UserId>\n"
        "    </LogonTrigger>\n"
        "  </Triggers>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>false</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <WakeToRun>false</WakeToRun>\n"
        "    <Enabled>true</Enabled>\n"
        "    <Hidden>false</Hidden>\n"
        "    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>\n"
        "    <Priority>7</Priority>\n"
        "  </Settings>\n"
        "  <Actions>\n"
        '    <Exec>\n'
        f"      <Command>{escape(command)}</Command>\n"
        f"      <Arguments>{escape(arguments)}</Arguments>\n"
        f"      <WorkingDirectory>{working}</WorkingDirectory>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def register_logon_task(xml: str, *, task_name: str, create) -> None:
    """Register one fixed task. A second call uses the same name."""

    if task_name != TASK_NAME:
        raise Forbidden("refusing to register any task but claude1-assignment-worker")
    if "LeastPrivilege" not in xml or "InteractiveToken" not in xml or "LogonTrigger" not in xml:
        raise Forbidden("logon task XML is missing the per-user limits")
    if "HighestAvailable" in xml or "S-1-5-18" in xml:
        raise Forbidden("logon task XML raises privileges")
    create(task_name, xml)


def unregister_logon_task(*, task_name: str, delete) -> None:
    """Remove that one task name and no other."""

    if task_name != TASK_NAME:
        raise Forbidden("refusing to delete any task but claude1-assignment-worker")
    delete(task_name)


def logon_once(root: Path, config: Path | None = None) -> int:
    """Idle at sign-in until a later build honors activation.

    This does not read the config directory and does not open a network client.
    """

    if config is not None and config.is_symlink():
        print('{"detail": "logon config path is a symlink", "error": "disabled", "exit_code": 2, "ok": false}')
        return 2
    _drop_secret_env()
    target = ensure_private_dir(root)
    enabled = target / "enabled"
    approved = target / "ACTIVATION_APPROVED"
    active = enabled.is_file() and enabled.read_text(encoding="utf-8").strip() == "true" and approved.is_file()
    if active:
        # This build still refuses activation. The flag is not a live switch.
        detail = "activation is not honored"
    else:
        detail = "logon idle"
    append_private_bytes(target / "logon.log", f"disabled {detail}\n".encode("utf-8"))
    print(json.dumps({"detail": detail, "error": "disabled", "exit_code": 0, "ok": False}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "emit-xml":
        print('{"ok": false, "error": "disabled", "exit_code": 2}')
        return 2
    parser = argparse.ArgumentParser(prog="startup_task emit-xml")
    parser.add_argument("--user", required=True)
    parser.add_argument("--user-sid", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--xml-out", required=True)
    parsed = parser.parse_args(args[1:])
    try:
        xml = build_logon_task_xml(
            user=parsed.user,
            user_sid=parsed.user_sid,
            python=Path(parsed.python),
            state=Path(parsed.state),
            config=Path(parsed.config),
        )
        Path(parsed.xml_out).write_bytes(xml.encode("utf-16"))
    except Forbidden as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"exit_code": 0, "ok": True, "task": TASK_NAME}, sort_keys=True))
    return 0


def _require_current_user(user: str) -> str:
    account = user.strip()
    folded = account.casefold()
    if not account or folded in _FORBIDDEN_USERS or folded.endswith("\\system"):
        raise Forbidden("logon task user must be the current user")
    if "\\" not in account and "/" not in account:
        raise Forbidden("logon task user must be the current user")
    return account


def _require_user_sid(user_sid: str) -> str:
    sid = user_sid.strip()
    if not sid.startswith("S-1-5-21-") or sid in _FORBIDDEN_SIDS:
        raise Forbidden("logon task SID must be the current user")
    return sid


def _require_path(path: Path) -> str:
    text = str(path)
    if not text or "\n" in text or "\r" in text:
        raise Forbidden("logon task path is empty")
    lowered = text.casefold()
    if "freeclaudecode" in lowered or "fcc-pilot" in lowered or "inkbound" in lowered:
        raise Forbidden("logon task path is a preserved install")
    return text


def _refuse_secret_text(*parts: str) -> None:
    blob = "\n".join(parts).casefold()
    for marker in ("xoxb-", "xoxp-", "github_pat_", "ghp_", "github_publish", "slack_bot"):
        if marker in blob:
            raise Forbidden("logon task command contains secret material")


def _drop_secret_env() -> None:
    from free_claude_code.assignments.execution import scrub_env

    kept = scrub_env(os.environ)
    for name in list(os.environ):
        if name not in kept:
            os.environ.pop(name, None)


if __name__ == "__main__":
    raise SystemExit(main())
