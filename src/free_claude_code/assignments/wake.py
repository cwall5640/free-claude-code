# SPDX-License-Identifier: AGPL-3.0-only
"""Keep the machine awake only while a task is running and the cord is in.

This calls SetThreadExecutionState. It does not change the power plan, call
powercfg, or request the display. On battery, and on any system that is not
Windows, it does nothing.
"""

import ctypes
import os
import threading
from collections.abc import Callable
from types import TracebackType

# Flags from WinBase.h. ES_DISPLAY_REQUIRED and ES_AWAYMODE_REQUIRED are not used.
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002
ES_AWAYMODE_REQUIRED = 0x00000040
ES_CONTINUOUS = 0x80000000


def hold_flags() -> int:
    """Ask Windows to stay up. The display flag is not included."""

    flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    if flags & (ES_DISPLAY_REQUIRED | ES_AWAYMODE_REQUIRED):
        raise RuntimeError("wake flags must not keep the display on")
    return flags


def clear_flags() -> int:
    """Drop a previous request. ES_CONTINUOUS alone clears the other flags."""

    return ES_CONTINUOUS


def windows_ac_status() -> str:
    """Return ac, battery, or unknown. Unknown is treated as not plugged in."""

    class _Power(ctypes.Structure):
        _fields_ = [
            ("ACLineStatus", ctypes.c_byte),
            ("BatteryFlag", ctypes.c_byte),
            ("BatteryLifePercent", ctypes.c_byte),
            ("SystemStatusFlag", ctypes.c_byte),
            ("BatteryLifeTime", ctypes.c_uint32),
            ("BatteryFullLifeTime", ctypes.c_uint32),
        ]

    status = _Power()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        return "unknown"
    if status.ACLineStatus == 1:
        return "ac"
    if status.ACLineStatus == 0:
        return "battery"
    return "unknown"


def windows_set_execution_state(flags: int) -> None:
    if flags & (ES_DISPLAY_REQUIRED | ES_AWAYMODE_REQUIRED):
        raise RuntimeError("wake flags must not keep the display on")
    ctypes.windll.kernel32.SetThreadExecutionState(flags)


class PluggedInWake:
    """Hold a system-required wake only on AC, and only inside this block."""

    def __init__(
        self,
        *,
        ac_status: Callable[[], str] | None = None,
        set_state: Callable[[int], None] | None = None,
        platform: str | None = None,
        interval: float = 30.0,
    ) -> None:
        self._platform = os.name if platform is None else platform
        self._ac_status = ac_status or windows_ac_status
        self._set_state = set_state or windows_set_execution_state
        self._interval = interval
        self._held = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def tick(self) -> None:
        """Re-check the cord. Set the wake on AC. Clear it on battery."""

        if self._platform != "nt":
            return
        if self._ac_status() == "ac":
            self._set_state(hold_flags())
            with self._lock:
                self._held = True
            return
        self.clear()

    def clear(self) -> None:
        if self._platform != "nt":
            return
        with self._lock:
            held = self._held
            self._held = False
        if held:
            self._set_state(clear_flags())

    def __enter__(self) -> "PluggedInWake":
        self.tick()
        if self._platform == "nt":
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="claude1-wake", daemon=True)
            self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        self.clear()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.tick()
            except Exception:
                self.clear()
                return
