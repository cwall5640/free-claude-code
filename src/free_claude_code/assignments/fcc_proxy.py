# SPDX-License-Identifier: AGPL-3.0-only
"""Start the original Free Claude Code proxy only for an enabled worker.

A disabled logon does not probe or start anything. The child process gets a
small environment with no publisher token and no Slack token. This module
does not copy the install or edit its config.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

from free_claude_code.assignments.errors import Forbidden

HEALTH_URL = "http://127.0.0.1:8082/health"
_LAUNCHER_NAME = "start-windows.ps1"
_KEEP_ENV = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PUBLIC",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


def default_fcc_launcher(profile: Path) -> Path:
    """The existing server script. It is not a second install."""

    return profile / "AppData" / "Local" / "Programs" / "FreeClaudeCode" / _LAUNCHER_NAME


def resolve_fcc_launcher(profile: Path, configured: str = "") -> Path:
    text = configured.strip()
    if not text:
        return default_fcc_launcher(profile)
    if not _is_absolute(text):
        raise Forbidden("fcc launcher must be an absolute path")
    if "\n" in text or "\r" in text:
        raise Forbidden("fcc launcher path is invalid")
    return Path(text)


def _is_absolute(text: str) -> bool:
    if text.startswith("/") or text.startswith("\\"):
        return True
    return len(text) >= 3 and text[1] == ":" and text[2] in "\\/"


def launcher_from_worker_file(config: Path | None, profile: Path) -> Path:
    """Read fcc_launcher from worker.json. Do not open the secret file."""

    configured = ""
    if config is not None:
        worker = config / "worker.json"
        if worker.is_symlink():
            raise Forbidden("worker identity path is a symlink")
        if worker.is_file():
            raw = json.loads(worker.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                configured = str(raw.get("fcc_launcher", "")).strip()
    return resolve_fcc_launcher(profile, configured)


def ensure_fcc_proxy(
    *,
    enabled: bool,
    launcher: Path,
    health_url: str = HEALTH_URL,
    probe: Callable[[str], int] | None = None,
    spawn: Callable[[list[str], dict[str, str]], None] | None = None,
    wait_seconds: float = 20.0,
    sleep: Callable[[float], None] | None = None,
    now: Callable[[], float] | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Return disabled, healthy, started, or down.

    disabled means the worker is off and this function did not touch the proxy.
    """

    if not enabled:
        return "disabled"
    url = _require_health(health_url)
    check = probe or _probe_health
    if check(url) == 200:
        return "healthy"
    if not launcher.is_file() or launcher.is_symlink():
        return "down"
    command = _launcher_argv(launcher)
    child_env = proxy_child_env(environ if environ is not None else os.environ)
    _refuse_secret_text(" ".join(command))
    (spawn or _spawn_detached)(command, child_env)
    clock = now or time.monotonic
    pause = sleep or time.sleep
    deadline = clock() + wait_seconds
    while clock() < deadline:
        if check(url) == 200:
            return "started"
        pause(0.25)
    return "down"


def proxy_child_env(source: Mapping[str, str]) -> dict[str, str]:
    """Keep the Windows process basics. Drop tokens, including publisher and Slack."""

    return {key: value for key, value in source.items() if key.upper() in _KEEP_ENV}


def _launcher_argv(launcher: Path) -> list[str]:
    suffix = launcher.suffix.lower()
    if suffix == ".ps1":
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(launcher)]
    if suffix == ".exe":
        return [str(launcher)]
    raise Forbidden("fcc launcher must be the existing install script")


def _require_health(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 8082:
        raise Forbidden("proxy health must be http://127.0.0.1:8082/health")
    if parsed.path not in {"/health"}:
        raise Forbidden("proxy health must be http://127.0.0.1:8082/health")
    if parsed.query or parsed.fragment:
        raise Forbidden("proxy health must be http://127.0.0.1:8082/health")
    return HEALTH_URL


def _probe_health(url: str) -> int:
    request = urllib.request.Request(_require_health(url), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0


def _spawn_detached(command: list[str], env: dict[str, str]) -> None:
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        close_fds=True,
        creationflags=flags,
        start_new_session=os.name != "nt",
    )


def _refuse_secret_text(text: str) -> None:
    folded = text.casefold()
    for marker in ("xoxb-", "xoxp-", "github_pat_", "ghp_", "github_publish", "slack_bot"):
        if marker in folded:
            raise Forbidden("fcc launcher command contains secret material")
