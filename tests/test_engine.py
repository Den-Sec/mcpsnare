import asyncio
import pytest
from mcprobe.models import ToolInfo
from mcprobe.engine import scan_session
import mcprobe.checks  # register checks

class FakeSession:
    async def list_tools(self):
        return [ToolInfo("read_doc", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})]
    async def call_tool(self, name, args):
        if "etc/passwd" in args.get("path", ""):
            return "root:x:0:0:root:/root:/bin/bash"
        return "ok"

@pytest.mark.asyncio
async def test_engine_confirms_traversal_end_to_end():
    findings = await scan_session(FakeSession(), oob=None, transport="stdio")
    assert any(f.check == "path_traversal" and f.confidence.value == "confirmed"
               for f in findings)


class FetchSession:
    """Tool with a 'url' param so SSRF generates an OOB probe."""
    async def list_tools(self):
        return [ToolInfo("fetch", "", {"type": "object",
                "properties": {"url": {"type": "string"}}, "required": ["url"]})]
    async def call_tool(self, name, args):
        return "ok"


class DelayedOOB:
    """Simulates a remote interactsh-style backend: the callback for a token
    only becomes visible after the in-loop probe round-trip completes, i.e. it
    is delivered asynchronously and only surfaces on a poll that happens later.
    interactions() therefore returns empty if polled inline (before the wait)
    and a hit once the deferred poll runs."""
    def __init__(self):
        self._delivered: set[str] = set()

    def new_token(self):
        import uuid
        token = uuid.uuid4().hex[:12]
        # The callback lands only after control returns to the event loop,
        # i.e. it is NOT visible to an inline (pre-poll) check. call_soon runs
        # before the engine resumes inside its poll-until-hit loop.
        asyncio.get_running_loop().call_soon(self._delivered.add, token)
        return token, f"http://oob.test/{token}"

    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self._delivered else []


@pytest.mark.asyncio
async def test_engine_defers_oob_eval_for_delayed_callback():
    # With deferral + the poll-until-hit loop, the delayed callback is caught.
    findings = await scan_session(FetchSession(), oob=DelayedOOB(),
                                  transport="http", oob_poll_interval=0.001, oob_timeout=0.1)
    assert any(f.check in ("ssrf", "cmd_injection") and f.confidence.value == "confirmed"
               for f in findings)


class CountResolveOOB:
    """A single-token OOB whose callback only becomes visible from the Nth
    interactions() call onward - simulating a remote callback that lands late."""
    def __init__(self, resolve_after):
        self.resolve_after = resolve_after
        self._calls = 0
        self._tok = None
    def new_token(self):
        self._tok = "tok"
        return self._tok, "http://oob/tok"
    def interactions(self, token):
        self._calls += 1
        return [{"path": "/tok"}] if (token == self._tok and self._calls >= self.resolve_after) else []


@pytest.mark.asyncio
async def test_engine_poll_catches_late_oob_callback():
    oob = CountResolveOOB(resolve_after=5)
    findings = await scan_session(FetchSession(), oob=oob, transport="http",
                                  check_ids=["ssrf"], oob_poll_interval=0.001, oob_timeout=1.0)
    assert any(f.check == "ssrf" and f.confidence.value == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_engine_poll_bounded_when_no_callback():
    oob = CountResolveOOB(resolve_after=10_000)
    findings = await scan_session(FetchSession(), oob=oob, transport="http",
                                  check_ids=["ssrf"], oob_poll_interval=0.001, oob_timeout=0.005)
    assert not any(f.check == "ssrf" for f in findings)


import sys
from pathlib import Path
from mcprobe.connect.session import stdio_session
import mcprobe.checks  # noqa: F401  (register checks)

_SERVER = str(Path(__file__).parent / "fixtures" / "vuln_server" / "server.py")


@pytest.mark.asyncio
async def test_scan_confirms_nested_array_enum_traversal():
    async with stdio_session([sys.executable, _SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio")
    confirmed = {(f.check, f.param) for f in findings if f.confidence.value == "confirmed"}
    assert ("path_traversal", "config.path") in confirmed   # nested object
    assert ("path_traversal", "paths[0]") in confirmed       # array item
    assert ("path_traversal", "path") in confirmed           # enum-gated tool (read_mode)


class CountingSession:
    """Records calibration calls and reports a benign response."""
    def __init__(self):
        self.calls = []
    async def list_tools(self):
        return [ToolInfo("echo", "", {"type": "object",
                "properties": {"text": {"type": "string"}}, "required": ["text"]})]
    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        return "benign output"


@pytest.mark.asyncio
async def test_engine_calibrates_once_per_tool():
    from mcprobe.engine import _CALIBRATION_CALLS
    sess = CountingSession()
    await scan_session(sess, oob=None, transport="stdio", check_ids=["info_leak"])
    calib = sess.calls[:_CALIBRATION_CALLS]
    assert len(calib) == _CALIBRATION_CALLS
    assert all(c == ("echo", {"text": "mcprobe"}) for c in calib)


@pytest.mark.asyncio
async def test_engine_populates_baseline_response_and_latency():
    captured = {}

    class SpyCheck:
        id = "spy"
        def generate(self, point, ctx):
            captured["baseline"] = ctx.baseline
            return []
        def evaluate(self, probe, response, ctx):
            return None

    from mcprobe.checks.base import REGISTRY
    REGISTRY["spy"] = SpyCheck()
    try:
        await scan_session(CountingSession(), oob=None, transport="stdio", check_ids=["spy"])
    finally:
        del REGISTRY["spy"]
    b = captured["baseline"]
    assert b is not None
    assert b.response == "benign output"
    assert b.latency >= 0.0


@pytest.mark.asyncio
async def test_engine_calibration_can_be_disabled():
    sess = CountingSession()
    await scan_session(sess, oob=None, transport="stdio", check_ids=["info_leak"], calibrate=False)
    assert len(sess.calls) == 1  # only the single info_leak probe, no calibration calls


def test_aggregate_latency_uses_min():
    from mcprobe.engine import _aggregate_latency
    assert _aggregate_latency([0.5, 0.1]) == 0.1
    assert _aggregate_latency([]) == 0.0


_SLOW_SERVER = str(Path(__file__).parent / "fixtures" / "slow_server" / "server.py")
_SECRET_SERVER = str(Path(__file__).parent / "fixtures" / "secret_server" / "server.py")


@pytest.mark.slow
@pytest.mark.asyncio
async def test_slow_safe_tool_no_time_based_fp():
    # Real ~6s tool. A fixed-5s oracle would false-fire; the calibrated relative
    # oracle must report NOTHING. (Slow: ~24s. Run with -m "not slow" to skip.)
    async with stdio_session([sys.executable, _SLOW_SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["cmd_injection"], aggressive=True)
    assert findings == []


@pytest.mark.asyncio
async def test_docs_secret_tool_no_info_leak_fp():
    # Tool whose benign output always contains secret-shaped strings. Because the
    # calibration baseline contains the same secrets, the probe triggers no diff.
    async with stdio_session([sys.executable, _SECRET_SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["info_leak"])
    assert findings == []


class MultiDelayedOOB:
    """Per-payload tokens (R-C2); every issued token resolves asynchronously after the
    probe round-trip (R-C1) - i.e. NOT visible to an inline pre-poll check, only after
    the loop yields once."""
    def __init__(self):
        self._n = 0
        self._delivered = set()
    def new_token(self):
        self._n += 1
        t = f"tok{self._n}"
        asyncio.get_running_loop().call_soon(self._delivered.add, t)
        return t, f"http://oob/{t}"
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self._delivered else []


class ShellSession:
    async def list_tools(self):
        return [ToolInfo("run", "", {"type": "object",
                "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]})]
    async def call_tool(self, name, args):
        return "ran"


@pytest.mark.asyncio
async def test_engine_confirms_cmd_oob_and_names_payload():
    findings = await scan_session(ShellSession(), oob=MultiDelayedOOB(), transport="stdio",
                                  check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.5)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1                 # deduped to one finding per (tool, param)
    assert "curl" in confirmed[0].payload      # the firing OOB separator is named


@pytest.mark.asyncio
async def test_engine_plumbs_aggressive_to_checks():
    captured = {}

    class SpyAgg:
        id = "spyagg"
        def generate(self, point, ctx):
            captured["aggressive"] = ctx.aggressive
            return []
        def evaluate(self, probe, response, ctx):
            return None

    from mcprobe.checks.base import REGISTRY
    REGISTRY["spyagg"] = SpyAgg()
    try:
        await scan_session(CountingSession(), oob=None, transport="stdio",
                           check_ids=["spyagg"], aggressive=True)
    finally:
        del REGISTRY["spyagg"]
    assert captured["aggressive"] is True


class ShellLikeOOB:
    """Records issued tokens+urls; a fake shell delivers a token's callback when it
    'executes' the matching payload."""
    def __init__(self):
        self.issued = {}      # token -> url
        self.delivered = set()
    def new_token(self):
        t = f"tok{len(self.issued) + 1}"
        url = f"http://oob/{t}"
        self.issued[t] = url
        return t, url
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self.delivered else []


def _shell_session(oob, recognizes):
    """A tool whose simulated shell 'executes' a payload (delivering its OOB callback)
    only if the payload contains one of `recognizes` (OS-specific command shapes)."""
    class _Sess:
        async def list_tools(self):
            return [ToolInfo("run", "", {"type": "object",
                    "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]})]
        async def call_tool(self, name, args):
            cmd = args.get("cmd", "")
            if any(r in cmd for r in recognizes):
                for tok, url in oob.issued.items():
                    if url in cmd:
                        oob.delivered.add(tok)
            return "ran"
    return _Sess()


@pytest.mark.asyncio
async def test_engine_confirms_powershell_oob():
    oob = ShellLikeOOB()
    sess = _shell_session(oob, recognizes=["iwr ", "curl.exe "])   # PowerShell-only shell
    findings = await scan_session(sess, oob=oob, transport="stdio", check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.05)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert ("iwr" in confirmed[0].payload) or ("curl.exe" in confirmed[0].payload)


@pytest.mark.asyncio
async def test_engine_confirms_cmd_exe_oob():
    oob = ShellLikeOOB()
    sess = _shell_session(oob, recognizes=["| curl ", "& curl "])  # cmd.exe-style shell
    findings = await scan_session(sess, oob=oob, transport="stdio", check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.05)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert ("| curl" in confirmed[0].payload) or ("& curl" in confirmed[0].payload)
