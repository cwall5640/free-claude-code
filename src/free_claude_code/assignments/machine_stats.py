# SPDX-License-Identifier: AGPL-3.0-only
"""Cheap, best-effort machine stats for assignment stage logs.

STALL-DIAG-01: run #21 vs #25 check-stage growth (81 -> 149 minutes) could
not be split into test time vs machine contention because no per-run
machine stats were recorded (the laptop sat at ~45% CPU on one evening
check vs ~3% at another launch, and nobody wrote either number down).
snapshot() is the number written down: platform, cpu_count, load average,
and memory used/total where the OS offers them cheaply.

Stdlib only, and it must never raise: a stats failure returns whatever
partial dict was gathered, because a diagnostics helper that can break
the check stage it observes would be worse than the gap it closes.
"""

import ctypes
import os
import platform
import sys
from contextlib import suppress


def _load_average() -> tuple[float, float, float] | None:
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        return None
    return (float(load[0]), float(load[1]), float(load[2]))


def _memory_windows() -> tuple[int | None, int | None]:
    """(used_bytes, total_bytes) via GlobalMemoryStatusEx, or (None, None)."""

    class _MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = _MemoryStatusEx()
    status.dwLength = ctypes.sizeof(_MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None, None
    total = int(status.ullTotalPhys)
    return total - int(status.ullAvailPhys), total


def _memory_linux() -> tuple[int | None, int | None]:
    """(used_bytes, total_bytes) from /proc/meminfo, or (None, None)."""

    values: dict[str, int] = {}
    with open("/proc/meminfo", encoding="ascii") as handle:
        for line in handle:
            name, _, rest = line.partition(":")
            if name in {"MemTotal", "MemAvailable"}:
                values[name] = int(rest.split()[0]) * 1024
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if total is None:
        return None, None
    used = total - available if available is not None else None
    return used, total


def _memory() -> tuple[int | None, int | None]:
    try:
        if sys.platform == "win32":
            return _memory_windows()
        if sys.platform.startswith("linux"):
            return _memory_linux()
    except Exception:
        pass
    return None, None


def snapshot() -> dict[str, object]:
    """One stats snapshot. Never raises; missing values are None."""

    stats: dict[str, object] = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "load_average": None,
        "memory_used_bytes": None,
        "memory_total_bytes": None,
    }
    with suppress(Exception):
        stats["load_average"] = _load_average()
    with suppress(Exception):
        used, total = _memory()
        stats["memory_used_bytes"] = used
        stats["memory_total_bytes"] = total
    return stats
