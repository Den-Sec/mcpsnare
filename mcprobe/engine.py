import asyncio
import math
import time
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
                       aggressive=False):
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
    for tool in tools:
        points = injection_points(tool)
        # ctx.baseline is mutated per tool. Only token-bearing probes defer
        # (cmd_injection OOB, ssrf) and they read ctx.oob, never ctx.baseline; keep
        # baseline-consuming oracles non-token so they evaluate inline under the
        # correct tool's baseline.
        ctx.baseline = await _calibrate(session, tool) if (calibrate and points) else None
        for point in points:
            for check in checks:
                for probe in check.generate(point, ctx):
                    start = time.monotonic()
                    try:
                        resp = await session.call_tool(tool.name, probe.args)
                    except Exception as e:
                        resp = f"error: {e}"
                    probe.meta["elapsed"] = time.monotonic() - start
                    if probe.token and oob is not None:
                        # Remote OOB callbacks may arrive later; defer evaluation.
                        deferred.append((check, probe, resp))
                    else:
                        collect(check.evaluate(probe, resp, ctx))

    if deferred:
        # Poll-until-hit: outstanding OOB callbacks may land later than a fixed wait.
        # Poll every oob_poll_interval up to oob_timeout, exiting early once all
        # outstanding tokens have resolved. A clean target is bounded by one timeout.
        tokens = [p.token for _, p, _ in deferred if p.token]
        polls = max(1, math.ceil(oob_timeout / oob_poll_interval)) if oob_poll_interval > 0 else 1
        for _ in range(polls):
            # Early-exit only when ALL outstanding tokens resolve. For a multi-token
            # check (cmd_injection issues 3 OOB tokens, one per separator) usually only
            # the working separator fires, so a vulnerable target waits the full timeout.
            # That is bounded (one per-scan timeout, not per-probe) and correct for M3.
            # M6/R-C3: replace the per-token interactions() calls with a single poll_all()
            # per iteration so real interactsh does one network round-trip, not N.
            if oob is not None and all(oob.interactions(t) for t in tokens):
                break
            await asyncio.sleep(oob_poll_interval)
        for check, probe, resp in deferred:
            collect(check.evaluate(probe, resp, ctx))
    return findings
