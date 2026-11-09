# SPDX-License-Identifier: AGPL-3.0-only
"""Private files for worker state.

POSIX mode 0o600 is not a Windows ACL. Every state file is hardened after it
exists and before its payload is stored, and again after the final replace.
"""

import os
import secrets
import stat
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden
from free_claude_code.assignments.secrets import refuse_symlink_or_reparse


def ensure_private_dir(path: Path) -> Path:
    """Create a directory and restrict it to the current user."""

    _refuse(path)
    path.mkdir(parents=True, exist_ok=True)
    _harden(path)
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import file_is_current_user_only

        if not file_is_current_user_only(path):
            raise Forbidden("state directory is not owned by the current user")
        return path
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise Forbidden("state directory is not private")
    return path


def write_private_bytes(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """Create or replace a file, then store bytes only after it is private."""

    _refuse(path)
    flags = _flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    os.close(fd)
    _harden(path)
    fd = os.open(path, _flags(os.O_WRONLY, os.O_TRUNC), 0o600)
    try:
        _write_all(fd, data)
        _fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    _harden(path)


def append_private_bytes(path: Path, data: bytes) -> None:
    """Append bytes to a private file. The file is hardened before the append."""

    _refuse(path)
    if not path.exists():
        try:
            fd = os.open(path, _flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL), 0o600)
        except FileExistsError:
            fd = -1
        else:
            os.close(fd)
    _harden(path)
    fd = os.open(path, _flags(os.O_WRONLY, os.O_CREAT, os.O_APPEND), 0o600)
    try:
        _write_all(fd, data)
        _fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    _harden(path)


def atomic_write_private(path: Path, data: bytes) -> None:
    """Write a sibling temp, harden it, replace the destination, then harden that."""

    ensure_private_dir(path.parent)
    _refuse(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        write_private_bytes(temporary, data, exclusive=True)
        os.replace(temporary, path)
    except Exception:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
        raise
    _harden(path)


def _refuse(path: Path) -> None:
    reparse = False
    if os.name == "nt" and (path.exists() or path.is_symlink()):
        from free_claude_code.assignments.windows_acl import is_reparse_point

        reparse = is_reparse_point(path)
    refuse_symlink_or_reparse(is_symlink=path.is_symlink(), reparse=reparse)


def _harden(path: Path) -> None:
    if os.name == "nt":
        from free_claude_code.assignments.windows_acl import harden_path

        harden_path(path)
        return
    os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _flags(*parts: int) -> int:
    flags = 0
    for part in parts:
        flags |= part
    if os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags | getattr(os, "O_BINARY", 0)


def _fchmod(fd: int, mode: int) -> None:
    if hasattr(os, "fchmod"):
        os.fchmod(fd, mode)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise Forbidden("private state write was incomplete")
        view = view[written:]
