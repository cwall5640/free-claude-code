# SPDX-License-Identifier: AGPL-3.0-only
"""Operator secret file. Values stay in this process and are never logged.

Storage guarantee
-----------------
POSIX: the file and its immediate parent must be regular objects owned by the
current uid, with no group or other permission bits. Symlinks are refused.
``chmod 0600`` is enforced with ``fstat`` after ``O_NOFOLLOW``.

Windows: ``st_mode`` is not a privacy check. Python often reports ``0o666``
for a writable file after ``os.chmod(path, 0o600)``. The file and its parent
must have a protected DACL whose only allow entry is the current user. If the
ACL cannot be read or restricted, loading and writing fail closed.

The publish, CI, and read tokens are separate names in that file. Only the
publisher process copies ``github_publish`` into an HTTP ``Authorization``
header. Test commands and the Claude process environment strip publisher and
CI tokens. ``proxy_auth`` is copied only into the Claude process, because that
is the local FCC bearer token, not a GitHub credential.
"""

import os
import stat
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.redact import redact

def refuse_symlink_or_reparse(*, is_symlink: bool, reparse: bool) -> None:
    """Reject a symlink or reparse point. This does not create either one."""

    if is_symlink or reparse:
        raise Forbidden("refusing a reparse point or symlink for secrets")


_NAMES = (
    "github_read",
    "github_ci",
    "github_publish",
    "grant_key",
    "proxy_auth",
    "slack_bot",
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

    def optional(self, name: str) -> str:
        if name not in _NAMES:
            raise Forbidden("unknown secret name")
        return self._values.get(name, "")


def posix_mode_is_private(mode: int, *, directory: bool) -> bool:
    """Owner-only bits. This is not used as the Windows decision."""

    if mode & 0o077:
        return False
    if directory:
        return bool(mode & stat.S_IXUSR and mode & stat.S_IRUSR)
    return bool(mode & stat.S_IRUSR)


def load_secret_file(path: Path) -> SecretFile:
    """Read a secret file after a same-handle privacy check."""

    try:
        raw = _read_private(path)
    except OSError as exc:
        raise Forbidden(f"cannot read secret file: {redact(str(exc))}") from None
    values: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name in _NAMES and value:
            values[name] = value
    return SecretFile(values)


def write_secret_file(path: Path, values: dict[str, str]) -> None:
    """Create a private secret file. The parent must be a dedicated directory."""

    parent = path.parent
    if parent.exists():
        _require_private_directory(parent)
    else:
        parent.mkdir(parents=True, exist_ok=False)
        _harden_new_directory(parent)
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    data = "".join(f"{name}={values[name]}\n" for name in _NAMES if name in values)
    _write_private(path, data.encode("utf-8"))
    _require_private_file(path)


def _read_private(path: Path) -> bytes:
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only, is_reparse_point

        if is_reparse_point(path) or is_reparse_point(path.parent):
            refuse_symlink_or_reparse(is_symlink=True, reparse=True)
        if not file_is_current_user_only(path) or not file_is_current_user_only(path.parent):
            raise Forbidden("Windows secret ACL is not limited to the current user")
        return path.read_bytes()
    return _posix_read(path)


def _write_private(path: Path, data: bytes) -> None:
    if os.name == "nt":
        path.write_bytes(data)
        from free_claude_code.assignments.windows_acl import harden_path

        harden_path(path)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fchmod(fd, 0o600)
        _require_posix_fd(fd, directory=False)
    finally:
        os.close(fd)


def _posix_read(path: Path) -> bytes:
    _require_private_directory(path.parent)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Forbidden("refusing a symlink or unreadable secret file") from exc
    try:
        _require_posix_fd(fd, directory=False)
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _harden_new_directory(path: Path) -> None:
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import harden_path

        harden_path(path)
        return
    os.chmod(path, 0o700)
    _require_private_directory(path)


def _require_private_directory(path: Path) -> None:
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only

        if not file_is_current_user_only(path):
            raise Forbidden("secret directory ACL is not limited to the current user")
        return
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise Forbidden("secret parent is not a directory")
    if info.st_uid != os.getuid():
        raise Forbidden("secret directory is not owned by the current user")
    if not posix_mode_is_private(stat.S_IMODE(info.st_mode), directory=True):
        raise Forbidden("secret directory is group or world accessible")


def _require_private_file(path: Path) -> None:
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only

        if not file_is_current_user_only(path):
            raise Forbidden("Windows secret ACL is not limited to the current user")
        return
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=False)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise Forbidden("secret path is not a regular file")
    if info.st_uid != os.getuid():
        raise Forbidden("secret file is not owned by the current user")
    if not posix_mode_is_private(stat.S_IMODE(info.st_mode), directory=False):
        raise Forbidden("secret file is group or world accessible")


def _require_posix_fd(fd: int, *, directory: bool) -> None:
    info = os.fstat(fd)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise Forbidden("secret object has the wrong file type")
    if info.st_uid != os.getuid():
        raise Forbidden("secret object is not owned by the current user")
    if not posix_mode_is_private(stat.S_IMODE(info.st_mode), directory=directory):
        raise Forbidden("secret object is group or world accessible")
