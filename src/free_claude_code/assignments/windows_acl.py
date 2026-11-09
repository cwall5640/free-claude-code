# SPDX-License-Identifier: AGPL-3.0-only
"""Windows DACL checks. chmod and st_mode are not used as a privacy proof.

Python on Windows reports a synthetic mode, often 0o666 for a writable file,
even after os.chmod(path, 0o600). These helpers read and replace the DACL.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

from free_claude_code.assignments.errors import Forbidden

_FILE_ALL_ACCESS = 0x001F01FF
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PRESENT = 0x0004
_SE_DACL_PROTECTED = 0x1000
_SE_FILE_OBJECT = 1
_ACL_REVISION = 2
_ACCESS_ALLOWED_ACE_TYPE = 0
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_INVALID_HANDLE = wintypes.HANDLE(-1).value
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_CREATE_ALWAYS = 2
_OPEN_EXISTING = 3
_FILE_SHARE_READ = 0x00000001


class _Acl(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_byte),
        ("Sbz1", ctypes.c_byte),
        ("AclSize", wintypes.WORD),
        ("AceCount", wintypes.WORD),
        ("Sbz2", wintypes.WORD),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_byte),
        ("AceFlags", ctypes.c_byte),
        ("AceSize", wintypes.WORD),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _ByHandle(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def acl_is_current_user_only(
    *,
    dacl_present: bool,
    dacl_protected: bool,
    allow_sids: tuple[str, ...],
    other_ace_count: int,
    user_sid: str,
) -> bool:
    """Pure policy shared by the Windows check and by unit tests."""

    return bool(
        dacl_present
        and dacl_protected
        and other_ace_count == 0
        and allow_sids == (user_sid,)
    )


def _libraries() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.InitializeAcl.restype = wintypes.BOOL
    advapi32.AddAccessAllowedAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    advapi32.AddAccessAllowedAce.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    return advapi32, kernel32


def current_user_sid() -> str:
    advapi32, kernel32 = _libraries()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise Forbidden("cannot query the current Windows user")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)
        ):
            raise Forbidden("cannot read the current Windows user token")
        user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        sid = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid)):
            raise Forbidden("cannot name the current Windows user")
        try:
            value = sid.value
        finally:
            kernel32.LocalFree(sid)
        if not value:
            raise Forbidden("current Windows user SID was empty")
        return value
    finally:
        kernel32.CloseHandle(token)


def _sid_pointer(text: str) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    advapi32, _kernel32 = _libraries()
    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(text, ctypes.byref(sid)):
        raise Forbidden("cannot encode the current Windows user SID")
    return sid, sid


def _private_acl(sid: ctypes.c_void_p) -> ctypes.Array[ctypes.c_char]:
    advapi32, _kernel32 = _libraries()
    sid_length = advapi32.GetLengthSid(sid)
    if not sid_length:
        raise Forbidden("cannot measure the current Windows user SID")
    # ACL header + ACCESS_ALLOWED_ACE (SidStart replaced by the full SID).
    acl_size = 8 + 12 - 4 + sid_length
    buffer = ctypes.create_string_buffer(acl_size)
    if not advapi32.InitializeAcl(buffer, acl_size, _ACL_REVISION):
        raise Forbidden("cannot initialize a secret-file ACL")
    if not advapi32.AddAccessAllowedAce(buffer, _ACL_REVISION, _FILE_ALL_ACCESS, sid):
        raise Forbidden("cannot add the current user to the secret-file ACL")
    return buffer


def _apply_private_dacl(path: Path, sid: ctypes.c_void_p, acl: ctypes.Array[ctypes.c_char]) -> None:
    advapi32, _kernel32 = _libraries()
    status = advapi32.SetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        acl,
        None,
    )
    if status != 0:
        raise Forbidden("cannot replace the secret-file ACL")


def file_is_current_user_only(path: Path) -> bool:
    try:
        return _inspect(path, directory=path.is_dir())[0]
    except Forbidden:
        return False


def _inspect(path: Path, *, directory: bool) -> tuple[bool, str]:
    advapi32, kernel32 = _libraries()
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= 0x02000000
    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE or handle is None:
        raise Forbidden("cannot open the secret path for an ACL check")
    try:
        info = _ByHandle()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise Forbidden("cannot stat the secret path by handle")
        from free_claude_code.assignments.secrets import refuse_symlink_or_reparse

        refuse_symlink_or_reparse(
            is_symlink=False,
            reparse=bool(info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT),
        )
        owner = ctypes.c_void_p()
        group = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        sacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        status = advapi32.GetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            ctypes.byref(group),
            ctypes.byref(dacl),
            ctypes.byref(sacl),
            ctypes.byref(descriptor),
        )
        if status != 0 or not descriptor:
            raise Forbidden("cannot read the secret-file security descriptor")
        try:
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise Forbidden("cannot read secret-file ACL flags")
            present = bool(control.value & _SE_DACL_PRESENT)
            protected = bool(control.value & _SE_DACL_PROTECTED)
            allow: list[str] = []
            other = 0
            if dacl:
                header = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
                for index in range(header.AceCount):
                    ace = ctypes.c_void_p()
                    if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                        raise Forbidden("cannot read a secret-file ACE")
                    ace_header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
                    if ace_header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                        other += 1
                        continue
                    sid_start = ctypes.c_void_p(ace.value + 8)
                    text = ctypes.c_wchar_p()
                    if not advapi32.ConvertSidToStringSidW(sid_start, ctypes.byref(text)):
                        other += 1
                        continue
                    try:
                        allow.append(text.value or "")
                    finally:
                        kernel32.LocalFree(text)
            user = current_user_sid()
            ok = acl_is_current_user_only(
                dacl_present=present,
                dacl_protected=protected,
                allow_sids=tuple(allow),
                other_ace_count=other,
                user_sid=user,
            )
            return ok, user
        finally:
            kernel32.LocalFree(descriptor)
    finally:
        kernel32.CloseHandle(handle)


STILL_ACTIVE = 259
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def process_is_running(opened: bool, exit_code: int | None) -> bool:
    """True only when the process handle is open and Windows still reports active.

    ``os.kill(pid, 0)`` terminates a process on Windows. Callers must use
    ``OpenProcess`` and ``GetExitCodeProcess`` instead.
    """

    return bool(opened and exit_code == STILL_ACTIVE)


def windows_pid_alive(pid: int) -> bool:
    """Query a PID. This does not signal the process."""

    if pid <= 0:
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return process_is_running(False, None)
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return process_is_running(True, None)
        return process_is_running(True, int(code.value))
    finally:
        kernel32.CloseHandle(handle)


def harden_path(path: Path) -> None:
    sid, owned = _sid_pointer(current_user_sid())
    try:
        acl = _private_acl(sid)
        _apply_private_dacl(path, sid, acl)
    finally:
        ctypes.windll.kernel32.LocalFree(owned)
    if not file_is_current_user_only(path):
        raise Forbidden("secret path ACL is not limited to the current user")
