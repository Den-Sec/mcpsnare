import asyncio
import time
from mcprobe.inject.mapper import injection_points
from mcprobe.checks.base import REGISTRY, CheckContext

async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_wait=2.0):
    ctx = CheckContext(oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth)
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
        for point in injection_points(tool):
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
        await asyncio.sleep(oob_wait)
        for check, probe, resp in deferred:
            collect(check.evaluate(probe, resp, ctx))
    return findings
