# STALL-DIAG-01 — Instrument the check stage: where do the minutes go?

**Owner:** Minerva (FCC assignment candidate)
**Filed by:** Minerva, at the Producer's direction, 2026-11-13
**Tracking issue:** #43
**Gate this informs:** any further check-stage timeout/limit change (TIMEOUT-02 and successors) — no limit moves again without the split this instrumentation produces.

## What this change adds

Diagnostics only. No timeout, cap, or limit value changes anywhere; no
behavior changes. Three recording points, all in
`src/free_claude_code/assignments/`:

1. **Per-stage durations** (`workflow.py`, `_execute`): every stage log
   entry — setup, model, test (the check stage), test_rerun (the
   EXEC-RETRY-01 failed-test re-run) — now carries `duration_seconds`,
   measured with `time.monotonic()` around the stage, including the
   error and timed_out entries (the duration runs up to the failure).
   Publish has no stage log entry today and gains none; its time stays
   visible only as the gap after the final check entry.
2. **Per-command evidence** (`execution.py`, `CommandEvidence`): every
   sandbox run now records `duration_seconds` (span from process start
   to the return of `communicate()` — so it includes the Windows
   pipe-drain wait after a kill, which is exactly the unbounded part)
   and `slowest_tests`: for a Playwright test command (the
   `is_playwright_test_command` shape check), the top 10 slowest tests
   parsed from the list-reporter output, as (test, seconds) with
   durations normalized to seconds from ms/s/m. Non-Playwright commands
   record an empty `slowest_tests`. The parser never raises on malformed
   output.
3. **Machine snapshot at check start** (`machine_stats.py`, new): the
   check stage's log entry carries `machine` — platform, cpu_count,
   load average (POSIX), and memory used/total (Windows
   GlobalMemoryStatusEx, Linux /proc/meminfo), stdlib only. The helper
   never raises; an unavailable stat is None. The check entry (or the
   timed_out entry, from the evidence the sandbox recorded before the
   raise) also carries `slowest_tests` copied from the check
   CommandEvidence.

Where the numbers surface: the run's stage logs (`logs` in the
candidate result — the same record FCC #20 timeout reporting reads) and
the sandbox's `CommandEvidence` list. Nothing new is posted anywhere;
no new file is written by a run.

## Why: run #21 vs run #25, from the verified record

The check stage grew by more than an hour between two runs of the same
test task (CLAUDE1-TEST-02, game repo issue #548), and the existing
records cannot say where the time went.

**Run #21** — base game `9a0736e4`, launched 2026-11-12 17:46 CT.

- Model pass done 17:50:11 CT: setup + model ≈ 4 minutes.
- Check command `npx playwright test --reporter=list --workers=1`,
  sandbox cap 3600s.
- The suite's `.last-run.json` was written 19:11:48 CT with status
  passed → suite wall ≈ 81 minutes. Claim stopped 19:11:50 CT.
- The mechanism that makes this unbounded: the sandbox kill kills only
  the npx/cmd shim on Windows. The Playwright node process keeps
  running, orphaned, holding the stdout pipe, so `communicate()`
  returns only when it exits. TimedOut is raised, but the wall clock
  is unbounded and there is no progress visibility — only the output
  tails are kept.

**Run #25** — base game `06f655a4`, 2026-11-13.

- Check started ≈ 12:41 CT, cap 7200s (deadline ≈ 14:41 CT). The
  orphaned suite finished 15:10:06 CT, status passed → suite wall
  ≈ 149 minutes.
- Both big WebKit e2e tests (`:435`, `:586`) failed attempt 1 with
  240s test timeouts and passed on the in-run retry — flaky. The
  `retries: 1` + trace-on-first-retry configuration came from game
  PR #619, merged between the two runs' bases, so a flaky test now
  costs a full 240s timeout + a full re-run + trace capture.
- Standalone timings at the same heads: `:435` pass 3.1m / fail 4.2m,
  `:586` pass 3.2m; the `game.spec` animation tests run 15–33s.

**The growth:** check stage 81 → 149 minutes (+68, +84%). Setup/model
stayed at minutes scale. Known contributors, unquantified per run:

- **Retry cost** (new in #25): two 240s timeouts plus two multi-minute
  re-runs plus traces. Bounded by the standalone timings at roughly
  15 minutes — real, but not 68.
- **Machine contention:** on the W6 evening the laptop sat at ~45%
  CPU during an idle check (Grok Bot processes + Windows Defender
  active) vs ~3% CPU at a W7 launch. No per-run stats were recorded —
  that absence is the gap the `machine` snapshot closes.
- **Outside-service waits:** the model stage depends on NVIDIA NIM
  responses; its duration is now separately logged by stage. No direct
  NIM latency records exist for #21/#25, and the model stage is not
  where the growth is — but the next run's stage durations will keep
  it visibly separate from check time.

## Recommended next step

1. Run the check suite alone **outside the sandbox** on the laptop —
   same command, same workspace — to get a clean per-test timing
   baseline unshaped by the sandbox kill/pipe behavior.
2. On the next real run, read the new stage durations, the check
   entry's `slowest_tests`, and its `machine` snapshot to split the
   check wall into test time vs stall time vs retry cost.
3. Only then consider further limit changes (the TIMEOUT-02 lane),
   sized from that split rather than from the wall clock alone.

**Flagged, not fixed here:** the orphan-process finding — the sandbox
kill terminates the npx/cmd shim but not the Playwright node process
tree on Windows, leaving `communicate()` blocked on the orphan's
stdout pipe. A process-tree kill on Windows is a candidate follow-up;
it is a behavior change to the sandbox and is deliberately out of
scope for this diagnostics-only change.

## Boundaries

- No timeout or limit changes; `runtime.json` untouched; packaging
  untouched.
- No changes to the original FCC install, the NVIDIA config, or the
  fcc-pilot-runner. No laptop deploy and no claude1 run as part of
  this change — it lands through the normal review lane and takes
  effect on the next deployed run.

— dev:minerva
