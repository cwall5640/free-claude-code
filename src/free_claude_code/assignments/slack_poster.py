# SPDX-License-Identifier: AGPL-3.0-only
"""Separate process that posts one HANDOFF line. Disabled until enabled is set.

The bot token is read from the private secret file inside this process.
It is not accepted on argv. Model and test environments must not receive it.
"""

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from free_claude_code.assignments.errors import Disabled, Forbidden
from free_claude_code.assignments.execution import scrub_env
from free_claude_code.assignments.secrets import load_secret_file, refuse_symlink_or_reparse

_HANDOFF = re.compile(
    r"HANDOFF: (?P<task>[a-z0-9]+(?:-[a-z0-9]+)*) \| "
    r"(?P<url>https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*) \| "
    r"(?P<sha>[0-9a-f]{40}) \| "
    r"(?P<status>PASS|HOLD|INCOMPLETE|STALE) \| "
    r"NEXT: (?P<actor>Casey|Cody|Minerva|Grok|RPG Dev|claude[1-9][0-9]*)\Z"
)
_CHANNEL = re.compile(r"C[A-Z0-9]{8,}\Z")
_BOT_TOKEN = re.compile(r"xoxb-[A-Za-z0-9-]+\Z")
_METHOD = "chat.postMessage"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise Forbidden("refusing a slack redirect")


def handoff_text(text: str) -> str:
    if _HANDOFF.fullmatch(text) is None:
        raise Forbidden("slack text is not a handoff line")
    return text


def slack_endpoint(api_base: str) -> str:
    """Only chat.postMessage on slack.com, or on a loopback fixture."""

    parsed = urlsplit(api_base.rstrip("/"))
    path = parsed.path.rstrip("/")
    if path.endswith(("/chat.update", "/chat.delete", "/files.upload")):
        raise Forbidden("slack method is not allowed")
    production = parsed.scheme == "https" and parsed.hostname == "slack.com" and path == "/api"
    fixture = parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and path == "/api"
    if not production and not fixture:
        raise Forbidden("slack api base is not allowed")
    if parsed.query or parsed.fragment:
        raise Forbidden("slack api base is not allowed")
    return f"{parsed.scheme}://{parsed.netloc}/api/{_METHOD}"


def post_handoff(
    *,
    enabled: bool,
    secrets_file: Path,
    channel_id: str,
    text: str,
    state_dir: Path,
    api_base: str = "https://slack.com/api",
    timeout: float = 10.0,
) -> str:
    """Post one handoff. A repeated line returns without a second request."""

    if not enabled:
        raise Disabled("slack poster is disabled")
    line = handoff_text(text)
    if not _CHANNEL.fullmatch(channel_id):
        raise Forbidden("refusing a slack channel that is not the configured channel")
    endpoint = slack_endpoint(api_base)
    token = load_secret_file(secrets_file).get("slack_bot")
    if token.startswith("xoxp-") or not _BOT_TOKEN.fullmatch(token):
        raise Forbidden("slack token must be a bot token")
    if token in line or token in endpoint or token in channel_id:
        raise Forbidden("slack token must not be placed in the message")
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    record = state_dir / "posted.txt"
    digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
    if digest in _read_posted(record):
        return "duplicate"
    _send(endpoint, token, channel_id, line, timeout)
    _remember(record, digest)
    return "posted"


def _send(endpoint: str, token: str, channel_id: str, text: str, timeout: float) -> None:
    if not endpoint.endswith("/" + _METHOD):
        raise Forbidden("slack method is not allowed")
    payload = json.dumps({"channel": channel_id, "text": text}, separators=(",", ":")).encode("utf-8")
    if token.encode("utf-8") in payload:
        raise Forbidden("slack token must not be placed in the message")
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(endpoint, data=payload, method="POST")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        finally:
            exc.close()
        raise Forbidden("slack post failed") from None
    except urllib.error.URLError as exc:
        raise Forbidden("slack post failed") from exc
    loaded = json.loads(raw.decode("utf-8"))
    if not isinstance(loaded, dict) or loaded.get("ok") is not True:
        raise Forbidden("slack post failed")


def _read_posted(path: Path) -> set[str]:
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def _remember(path: Path, digest: str) -> None:
    seen = _read_posted(path)
    seen.add(digest)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, ("".join(f"{item}\n" for item in sorted(seen))).encode("utf-8"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--config":
        print('{"ok": false, "error": "disabled", "exit_code": 2}')
        return 2
    raw = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    for name in list(os.environ):
        if name not in scrub_env(os.environ):
            os.environ.pop(name, None)
    try:
        result = post_handoff(
            enabled=bool(raw.get("enabled", False)),
            secrets_file=Path(raw["secrets_file"]),
            channel_id=str(raw["channel_id"]),
            text=str(raw["text"]),
            state_dir=Path(raw["state_dir"]),
            api_base=str(raw.get("api_base") or "https://slack.com/api"),
        )
    except (Disabled, Forbidden) as exc:
        print(json.dumps({"ok": False, "error": exc.code, "exit_code": 2}))
        return 2
    print(json.dumps({"ok": True, "result": result, "exit_code": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
