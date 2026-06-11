import asyncio
import math
import time
from dataclasses import replace
from mcprobe.inject.mapper import injection_points, build_baseline
from mcprobe.checks.base import REGISTRY, CheckContext
from mcprobe.models import ToolBaseline

_CALIBRATION_CALLS = 2


def _aggregate_latency(latencies):
    # Minimum = the tool's intrinsic latency floor. A single slow outlier must NOT
    # inflate the baseline, which would raise the timing-oracle margin and mask real
    # injected delays (false negatives). FP-resistance comes from the margin formula
    # (see cmd_injection._LATENCY_MULT), not from an inflated baseline.
    return min(latencies) if latencies else 0.0


async def _calibrate(session, tool):
    """Issue benign control calls to learn this tool's baseline latency + response.

    Uses the schema-valid baseline args (no payloads). Returns a ToolBaseline with
    the minimum (floor) latency over _CALIBRATION_CALLS calls (see _aggregate_latency)
    and the first response text.
    """
    args = build_baseline(tool.input_schema)
    latencies, response = [], ""
    for i in range(_CALIBRATION_CALLS):
        start = time.monotonic()
        try:
            r = await session.call_tool(tool.name, args)
        except Exception as e:
            r = f"error: {e}"
        latencies.append(time.monotonic() - start)
        if i == 0:
            response = r
    return ToolBaseline(latency=_aggregate_latency(latencies), response=response)


async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_poll_interval=2.5, oob_timeout=20.0, calibrate=True,
                       aggressive=False, concurrency=4):
    ctx = CheckContext(oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth, aggressive=aggressive)
    tools = await session.list_tools()
    checks = [c for cid, c in REGISTRY.items() if not check_ids or cid in check_ids]
    findings, seen = [], set()

    def collect(finding):
        if not finding:
            return
        key = (finding.check, finding.tool, finding.param)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    deferred = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _call(tool, probe):
        start = time.monotonic()
        try:
            resp = await session.call_tool(tool.name, probe.args)
        except Exception as e:
            resp = f"error: {e}"
        probe.meta["elapsed"] = time.monotonic() - start
        return resp

    def _dispatch(tool_ctx, check, probe, resp):
        # await-free -> atomic under asyncio's single thread. Carry tool_ctx into the
        # deferred tuple too, so all three dispatch paths evaluate under the probe's
        # own per-tool context (no hidden "deferred must not read baseline" invariant).
        if probe.token and oob is not None:
            deferred.append((check, probe, resp, tool_ctx))
        else:
            collect(check.evaluate(probe, resp, tool_ctx))

    async def _run_concurrent(tool, tool_ctx, check, probe):
        async with sem:
            resp = await _call(tool, probe)
        _dispatch(tool_ctx, check, probe, resp)

    timed = []   # time-based probes: run serially, uncontended (see below)
    tasks = []
    for tool in tools:
        points = injection_points(tool)
        # Per-tool context: concurrent tools must NOT share a mutated baseline.
        baseline = await _calibrate(session, tool) if (calibrate and points) else None
        tool_ctx = replace(ctx, baseline=baseline)
        for point in points:
            for check in checks:
                for probe in check.generate(point, tool_ctx):
                    if probe.meta.get("time_based"):
                        timed.append((tool, tool_ctx, check, probe))
                    else:
                        tasks.append(_run_concurrent(tool, tool_ctx, check, probe))
    if tasks:
        await asyncio.gather(*tasks)
    # Time-based probes depend on uncontended latency: a concurrent/queued call would
    # inflate probe.meta["elapsed"] and false-fire the timing oracle. Run them strictly
    # serially, after the concurrent phase, so each measures the tool's true latency.
    for tool, tool_ctx, check, probe in timed:
        resp = await _call(tool, probe)
        _dispatch(tool_ctx, check, probe, resp)

    if deferred:
        # Poll-until-hit: outstanding OOB callbacks may land later than a fixed wait.
        # Poll every oob_poll_interval up to oob_timeout, exiting early once all
        # outstanding tokens have resolved. A clean target is bounded by one timeout.
        tokens = [p.token for _, p, _, _ in deferred if p.token]
        polls = max(1, math.ceil(oob_timeout / oob_poll_interval)) if oob_poll_interval > 0 else 1
        for _ in range(polls):
            # One round-trip per iteration via poll_all(). Early-exit only when ALL
            # outstanding tokens resolve; a multi-token check usually fires just one
            # separator, so a vulnerable target waits the bounded timeout (per-scan,
            # not per-probe) - acceptable and correct.
            if oob is not None:
                hits = oob.poll_all()
                if all(hits.get(t) for t in tokens):
                    break
            await asyncio.sleep(oob_poll_interval)
        for check, probe, resp, tool_ctx in deferred:
            collect(check.evaluate(probe, resp, tool_ctx))
    return findings
