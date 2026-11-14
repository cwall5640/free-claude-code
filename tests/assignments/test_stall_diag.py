# SPDX-License-Identifier: AGPL-3.0-only
# ruff: noqa: RUF001 — the fixtures are literal Playwright reporter output;
# the U+203A angle quote in them is data, not punctuation.
"""STALL-DIAG-01: duration/slowest-test evidence and the machine snapshot.

The sandbox and the parser are real; the Playwright run is a shim
executable named npx that prints canned list-reporter output, so no
Node install is needed. The shim tests are POSIX-only (the shim is an
executable script); the parser, evidence-default, and machine-stats
tests run everywhere.
"""

import os
import stat
import sys
from pathlib import Path

import pytest

from free_claude_code.assignments import machine_stats
from free_claude_code.assignments.errors import TimedOut
from free_claude_code.assignments.execution import (
    CommandEvidence,
    NativeCommandApproval,
    Sandbox,
    parse_playwright_slowest,
)
from free_claude_code.assignments.models import ModelProvenance, Scope, TaskManifest

_PLAYWRIGHT_OUTPUT = (
    "Running 4 tests using 1 worker\n"
    "\n"
    "  ✓  1 [webkit] › tests/e2e-prologue-tutorial.spec.js:435:1 › opens the tutorial (3.1m)\n"
    "  ✘  2 [webkit] › tests/e2e-prologue-tutorial.spec.js:586:3 › finishes the tutorial (4.2m)\n"
    "  ✓  3 [webkit] › tests/game.spec.js:913:5 › animates the channel (15.2s)\n"
    "  ✓  4 [webkit] › tests/game.spec.js:936:5 › shows a shockwave (800ms)\n"
    "\n"
    "  4 passed (9.5m)\n"
)

_SLOWEST = (
    ("[webkit] › tests/e2e-prologue-tutorial.spec.js:586:3 › finishes the tutorial", 252.0),
    ("[webkit] › tests/e2e-prologue-tutorial.spec.js:435:1 › opens the tutorial", 186.0),
    ("[webkit] › tests/game.spec.js:913:5 › animates the channel", 15.2),
    ("[webkit] › tests/game.spec.js:936:5 › shows a shockwave", 0.8),
)


def _manifest() -> TaskManifest:
    return TaskManifest(
        task_key="cwall5640/fixture#7",
        owner="cwall5640",
        repo="fixture",
        issue_number=7,
        issue_revision="fixture-revision",
        title_redacted="probe",
        base_branch="dev",
        base_sha="abc",
        scope=Scope(("src",), 1000),
        model=ModelProvenance(),
    )


def _npx_shim(tmp_path: Path, body: str) -> tuple[str, ...]:
    shim = tmp_path / "npx"
    shim.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return (str(shim), "playwright", "test", "--reporter=list", "--workers=1")


posix_only = pytest.mark.skipif(
    os.name == "nt", reason="the npx shim is a POSIX executable script"
)


# ------------------------------------------------------------- parser


def test_parser_normalizes_units_and_sorts_slowest_first() -> None:
    assert parse_playwright_slowest(_PLAYWRIGHT_OUTPUT) == _SLOWEST


def test_parser_units_ms_s_m_h() -> None:
    output = "\n".join(
        [
            "  ✓  1 [webkit] › a.spec.js:1:1 › hour test (1.5h)",
            "  ✓  2 [webkit] › a.spec.js:2:1 › minute test (2m)",
            "  ✓  3 [webkit] › a.spec.js:3:1 › second test (45s)",
            "  ✓  4 [webkit] › a.spec.js:4:1 › milli test (250ms)",
        ]
    )
    assert parse_playwright_slowest(output) == (
        ("[webkit] › a.spec.js:1:1 › hour test", 5400.0),
        ("[webkit] › a.spec.js:2:1 › minute test", 120.0),
        ("[webkit] › a.spec.js:3:1 › second test", 45.0),
        ("[webkit] › a.spec.js:4:1 › milli test", 0.25),
    )


def test_parser_keeps_only_the_ten_slowest() -> None:
    lines = [
        f"  ✓  {index} [webkit] › a.spec.js:{index}:1 › test {index} ({index}s)"
        for index in range(1, 13)
    ]
    slowest = parse_playwright_slowest("\n".join(lines))
    assert len(slowest) == 10
    assert slowest[0][1] == 12.0
    assert slowest[-1][1] == 3.0


def test_parser_ignores_summaries_and_malformed_lines() -> None:
    output = "\n".join(
        [
            "",
            "Running 31 tests using 1 worker",
            "  5 passed (2.1m)",
            "  1 failed",
            "a line with a duration but no test chain (3s)",
            "  ✓  1 [webkit] › a.spec.js:1:1 › no duration",
            "  ✓  2 [webkit] › a.spec.js:2:1 › bad unit (3.1x)",
            "  ✓  3 [webkit] › a.spec.js:3:1 › bad amount (xs)",
            "  ✓  4 [webkit] › a.spec.js:4:1 › unbalanced (3.1m",
            "garbage ››› (((",
            "  ✓  5 [webkit] › a.spec.js:5:1 › the one good line (2s)",
        ]
    )
    assert parse_playwright_slowest(output) == (
        ("[webkit] › a.spec.js:5:1 › the one good line", 2.0),
    )
    assert parse_playwright_slowest("") == ()


# ------------------------------------------------------------- sandbox


@posix_only
def test_sandbox_evidence_carries_duration_and_slowest(tmp_path: Path) -> None:
    argv = _npx_shim(tmp_path, f"import sys\nsys.stdout.write({_PLAYWRIGHT_OUTPUT!r})\n")
    manifest = _manifest()
    sandbox = Sandbox(tmp_path, allowed=(argv,), timeout_seconds=30.0)
    evidence = sandbox.run(
        NativeCommandApproval(manifest.manifest_id, argv, "author"),
        manifest=manifest,
        head_sha="abc",
    )
    assert evidence.returncode == 0
    assert evidence.duration_seconds > 0
    assert evidence.slowest_tests == _SLOWEST


def test_sandbox_non_playwright_command_has_duration_but_no_slowest(
    tmp_path: Path,
) -> None:
    # The output is Playwright-shaped; the command is not, so the parse
    # must not happen — gating is by command shape, not by content.
    argv = (sys.executable, "-c", f"import sys; sys.stdout.write({_PLAYWRIGHT_OUTPUT!r})")
    manifest = _manifest()
    sandbox = Sandbox(tmp_path, allowed=(argv,), timeout_seconds=30.0)
    evidence = sandbox.run(
        NativeCommandApproval(manifest.manifest_id, argv, "author"),
        manifest=manifest,
        head_sha="abc",
    )
    assert evidence.returncode == 0
    assert evidence.duration_seconds > 0
    assert evidence.slowest_tests == ()


@posix_only
def test_sandbox_timed_out_evidence_keeps_duration_and_partial_slowest(
    tmp_path: Path,
) -> None:
    first_line = _PLAYWRIGHT_OUTPUT.splitlines()[2]
    body = (
        f"import sys, time\nprint({first_line!r}, flush=True)\ntime.sleep(5)\n"
    )
    argv = _npx_shim(tmp_path, body)
    manifest = _manifest()
    sandbox = Sandbox(tmp_path, allowed=(argv,), timeout_seconds=0.5)
    with pytest.raises(TimedOut):
        sandbox.run(
            NativeCommandApproval(manifest.manifest_id, argv, "author"),
            manifest=manifest,
            head_sha="abc",
        )
    evidence = sandbox.evidence[-1]
    assert evidence.timed_out is True
    assert evidence.duration_seconds >= 0.4
    assert evidence.slowest_tests == (_SLOWEST[1],)


def test_command_evidence_diagnostic_fields_default_empty() -> None:
    evidence = CommandEvidence(
        argv=("probe",),
        cwd=".",
        returncode=0,
        python_version="3",
        head_sha="abc",
        manifest_id="m",
        stdout_tail="",
        stderr_tail="",
        timed_out=False,
        cancelled=False,
        passed=1,
        failed=0,
        skipped=0,
        flaky=0,
        browser="not_checked",
    )
    assert evidence.duration_seconds == 0.0
    assert evidence.slowest_tests == ()


# ------------------------------------------------------------- machine stats


def test_machine_snapshot_shape() -> None:
    snapshot = machine_stats.snapshot()
    assert isinstance(snapshot["platform"], str)
    assert snapshot["platform"]
    assert snapshot["cpu_count"] == os.cpu_count()
    assert "load_average" in snapshot
    assert "memory_used_bytes" in snapshot
    assert "memory_total_bytes" in snapshot
    if sys.platform.startswith("linux"):
        load = snapshot["load_average"]
        assert isinstance(load, tuple) and len(load) == 3
        used = snapshot["memory_used_bytes"]
        total = snapshot["memory_total_bytes"]
        assert isinstance(used, int) and isinstance(total, int)
        assert 0 < used <= total


def test_machine_snapshot_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> tuple[int | None, int | None]:
        raise RuntimeError("stats unavailable")

    monkeypatch.setattr(machine_stats, "_memory", _boom)
    monkeypatch.setattr(os, "getloadavg", None)
    snapshot = machine_stats.snapshot()
    assert snapshot["memory_used_bytes"] is None
    assert snapshot["memory_total_bytes"] is None
    assert snapshot["load_average"] is None
    assert snapshot["cpu_count"] == os.cpu_count()
