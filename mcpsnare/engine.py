import asyncio
import math
import re
import time
from dataclasses import replace
from mcpsnare.inject.mapper import injection_points, build_baseline
from mcpsnare.checks.base import REGISTRY, PASSIVE_REGISTRY, CheckContext
from mcpsnare.models import ToolBaseline, Finding, Severity, Confidence

_CALIBRATION_CALLS = 2

# Fraction of probed tools whose benign baseline must look like a connection error
# before the scan flags the backend as unreachable (active checks inconclusive).
_UNREACHABLE_RATIO = 0.8

# Connection-error-shaped baselines. Matches both mcpsnare's own swallow ("error: ..."
# when call_tool raises) AND downstream strings from proxy servers that catch the
# transport error and return it as normal tool output (e.g. the revit-mcp proxy returns
# "Error: All connection attempts failed" / "...actively refused it").
_CONN_ERR = re.compile(
    r"(?i)(^error:\s|connection\s+(refused|reset|attempts\s+failed)|connection\s+timed\s*out|"
    r"actively\s+refused|getaddrinfo|name or service not known|max retries|"
    r"winerror\s*10061|errno\s*(111|61|10061)|failed to establish|connect call failed)")


class _RateGate:
    """Serialises probe starts to at most `rate` per second (None/0 = unlimited)."""
    def __init__(self, rate):
        self.interval = (1.0 / rate) if rate else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            self._next = max(now, self._next) + self.interval
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)


def _aggregate_latency(latencies):
    # Minimum = the tool's intrinsic latency floor. A single slow outlier must NOT
    # inflate the baseline, which would raise the timing-oracle margin and mask real
    # injected delays (false negatives). FP-resistance comes from the margin formula
    # (see cmd_injection._LATENCY_MULT), not from an inflated baseline.
    return min(latencies) if latencies else 0.0


async def _calibrate(session, tool, gate=None):
    """Issue benign control calls to learn this tool's baseline latency + response.

    Uses the schema-valid baseline args (no payloads). Returns a ToolBaseline with
    the minimum (floor) latency over _CALIBRATION_CALLS calls (see _aggregate_latency)
    and the first response text.
    """
    args = build_baseline(tool.input_schema)
    latencies, response = [], ""
    for i in range(_CALIBRATION_CALLS):
        if gate is not None:
            await gate.wait()
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
                       aggressive=False, concurrency=4, rate=None):
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

    # Passive lenses: inspect the tool manifest (name/description/schema) with ZERO
    # tool calls, before any active probing. This is what makes a vetting scan honest
    # against a thin proxy or a dead backend - a declared arbitrary-code-execution tool
    # is surfaced from the manifest even when active checks can confirm nothing.
    passive_checks = [c for cid, c in PASSIVE_REGISTRY.items() if not check_ids or cid in check_ids]
    for tool in tools:
        for pcheck in passive_checks:
            try:
                for f in pcheck.inspect(tool, ctx):
                    collect(f)
            except Exception:
                pass  # a passive check must never break the scan

    deferred = []
    sem = asyncio.Semaphore(max(1, concurrency))
    gate = _RateGate(rate)

    async def _call(tool, probe):
        await gate.wait()
        start = time.monotonic()
        try:
            resp = await session.call_tool(tool.name, probe.args)
        except Exception as e:
            resp = f"error: {e}"
        probe.meta["elapsed"] = time.monotonic() - start
        if probe.meta.get("needs_unauth") and call_tool_unauth is not None:
            await gate.wait()
            try:
                probe.meta["unauth_response"] = await call_tool_unauth(tool.name, probe.args)
            except Exception:
                probe.meta["unauth_response"] = None
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
    probed = errored = 0   # backend-reachability accounting (see below)
    for tool in tools:
        points = injection_points(tool)
        # Per-tool context: concurrent tools must NOT share a mutated baseline.
        baseline = await _calibrate(session, tool, gate) if (calibrate and points) else None
        tool_ctx = replace(ctx, baseline=baseline)
        if baseline is not None:
            probed += 1
            if _CONN_ERR.search(baseline.response or ""):
                errored += 1
        for point in points:
            for check in checks:
                for probe in check.generate(point, tool_ctx):
                    if probe.meta.get("time_based"):
                        timed.append((tool, tool_ctx, check, probe))
                    else:
                        tasks.append(_run_concurrent(tool, tool_ctx, check, probe))
    # "Empty != secure": if most probed tools returned connection-error-shaped baselines
    # the backend is effectively down and the active checks proved nothing. Emit one
    # INFO note so a clean report is not misread. Gated to the full scan (check_ids is
    # None) so the second, resource-only scan pass does not duplicate it.
    if check_ids is None and probed and (errored / probed) >= _UNREACHABLE_RATIO:
        collect(Finding(
            check="reachability", tool="(scan)", param="(all)",
            severity=Severity.INFO, confidence=Confidence.TENTATIVE, cwe="",
            title="Most tools errored on benign calls - active checks inconclusive",
            payload="(scan diagnostic)",
            evidence=(f"{errored}/{probed} probed tools returned error-shaped baselines "
                      f"(backend unreachable, or rejecting the benign probe input). Active injection "
                      f"checks cannot confirm anything when calls do not reach a working handler; an "
                      f"EMPTY active-scan result here does NOT mean the target is secure - rely on the "
                      f"passive capability lens and re-run against a live, correctly-configured backend."),
            remediation="Re-run with the target's real backend/dependencies live and valid inputs, or treat active-check results as inconclusive."))
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
