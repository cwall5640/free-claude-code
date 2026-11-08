# SPDX-License-Identifier: AGPL-3.0-only
"""Load operator secrets from a mode-0600 file. Never print the values."""

import os
import stat
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.redact import redact

_NAMES = (
    "github_read",
    "github_ci",
    "github_publish",
    "grant_key",
    "proxy_auth",
)


class SecretFile:
    """Secrets stay in this object. Repr and status text do not include them."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def __repr__(self) -> str:
        return "SecretFile([redacted])"

    def get(self, name: str) -> str:
        if name not in _NAMES:
            raise Forbidden("unknown secret name")
        value = self._values.get(name, "")
        if not value:
            raise Forbidden(f"missing secret {name}")
        return value


def load_secret_file(path: Path) -> SecretFile:
    """Refuse a secret file the group or other users can read."""

    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise Forbidden(f"cannot read secret file: {redact(str(exc))}") from None
    if not stat.S_ISREG(mode):
        raise Forbidden("secret path is not a regular file")
    if mode & 0o077:
        raise Forbidden("secret file must be mode 0600")
    parent_mode = path.parent.stat().st_mode
    if parent_mode & 0o077:
        raise Forbidden("secret directory must be mode 0700")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name in _NAMES and value:
            values[name] = value
    return SecretFile(values)


def write_secret_file(path: Path, values: dict[str, str]) -> None:
    """Create a secret file for tests and later operator setup. Values are not logged."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    data = "".join(f"{name}={values[name]}\n" for name in _NAMES if name in values)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
