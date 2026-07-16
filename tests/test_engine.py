import asyncio
import pytest
from mcpsnare.models import ToolInfo
from mcpsnare.engine import scan_session
import mcpsnare.checks  # register checks

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

    def poll_all(self):
        return {t: [{"path": f"/{t}"}] for t in self._delivered}


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
    def poll_all(self):
        self._calls += 1
        hit = (self._tok is not None and self._calls >= self.resolve_after)
        return {self._tok: [{"path": "/tok"}]} if hit else {}


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
from mcpsnare.connect.session import stdio_session
import mcpsnare.checks  # noqa: F401  (register checks)

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
    from mcpsnare.engine import _CALIBRATION_CALLS
    sess = CountingSession()
    await scan_session(sess, oob=None, transport="stdio", check_ids=["info_leak"])
    calib = sess.calls[:_CALIBRATION_CALLS]
    assert len(calib) == _CALIBRATION_CALLS
    assert all(c == ("echo", {"text": "mcpsnare"}) for c in calib)


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

    from mcpsnare.checks.base import REGISTRY
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
    from mcpsnare.engine import _aggregate_latency
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
    def poll_all(self):
        return {t: [{"path": f"/{t}"}] for t in self._delivered}


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

    from mcpsnare.checks.base import REGISTRY
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
    def poll_all(self):
        return {t: [{"path": f"/{t}"}] for t in self.delivered}


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


class ManyToolsSession:
    """N tools, each call sleeps a little - lets concurrency beat sequential."""
    def __init__(self, n, delay=0.02):
        self.n, self.delay = n, delay
    async def list_tools(self):
        return [ToolInfo(f"t{i}", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})
                for i in range(self.n)]
    async def call_tool(self, name, args):
        await asyncio.sleep(self.delay)
        return "root:x:0:0:" if "etc/passwd" in args.get("path", "") else "ok"


@pytest.mark.asyncio
async def test_engine_concurrency_identical_findings():
    seq = await scan_session(ManyToolsSession(6), oob=None, transport="stdio",
                             check_ids=["path_traversal"], concurrency=1)
    conc = await scan_session(ManyToolsSession(6), oob=None, transport="stdio",
                              check_ids=["path_traversal"], concurrency=6)
    seq_keys = {(f.check, f.tool, f.param) for f in seq}
    conc_keys = {(f.check, f.tool, f.param) for f in conc}
    assert seq_keys == conc_keys and len(conc_keys) == 6  # one traversal finding per tool


@pytest.mark.asyncio
async def test_engine_concurrency_is_faster():
    import time
    s = ManyToolsSession(8, delay=0.03)
    t0 = time.monotonic()
    await scan_session(s, oob=None, transport="stdio", check_ids=["path_traversal"], concurrency=1)
    seq_t = time.monotonic() - t0
    t0 = time.monotonic()
    await scan_session(ManyToolsSession(8, delay=0.03), oob=None, transport="stdio",
                       check_ids=["path_traversal"], concurrency=8)
    conc_t = time.monotonic() - t0
    assert conc_t < seq_t * 0.7  # materially faster


@pytest.mark.asyncio
async def test_engine_rate_limit_caps_request_rate():
    import time
    s = ManyToolsSession(6, delay=0.0)
    t0 = time.monotonic()
    await scan_session(s, oob=None, transport="stdio", check_ids=["path_traversal"],
                       concurrency=6, rate=20.0)
    elapsed = time.monotonic() - t0
    # path_traversal: 2 probes/tool x 6 + calibration 2x6 = ~24 calls / 20 rps ~ 1.1s
    assert elapsed >= 0.4  # throttled well above the unthrottled ~0s


@pytest.mark.asyncio
async def test_engine_auth_bypass_fires_over_async_unauth():
    class AuthSession:
        async def list_tools(self):
            return [ToolInfo("admin", "", {"type": "object",
                    "properties": {"x": {"type": "string"}}, "required": ["x"]})]
        async def call_tool(self, name, args):
            return "secret data"          # authed call returns the protected data

    async def unauth(name, args):          # ASYNC unauth callable, like Session.call_tool
        return "secret data"               # no-auth ALSO returns it -> bypass

    findings = await scan_session(AuthSession(), oob=None, transport="http",
                                  call_tool_unauth=unauth, check_ids=["auth_bypass"],
                                  calibrate=False)
    assert any(f.check == "auth_bypass" and f.confidence.value == "confirmed" for f in findings)


from mcpsnare.connect.resources import ResourceToolView


class FakeResourceSession:
    """A vulnerable resource template file:///{path} that 'reads' the path - returns a
    traversal canary when the path escapes, like a real path-traversal-vulnerable read."""
    async def list_resource_templates(self):
        return [("read_file", "file:///{path}")]
    async def read_resource(self, uri):
        return "root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in uri else "not found"


@pytest.mark.asyncio
async def test_engine_confirms_traversal_in_resource_template():
    view = ResourceToolView(FakeResourceSession())
    findings = await scan_session(view, oob=None, transport="stdio",
                                  check_ids=["path_traversal"])
    confirmed = [f for f in findings
                 if f.check == "path_traversal" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].param == "path"   # the templated URI param is the injection point


_TOOLS_ONLY_SERVER = str(Path(__file__).parent / "fixtures" / "tools_only_server" / "server.py")


@pytest.mark.asyncio
async def test_scan_tools_only_server_without_resources_does_not_crash():
    # Regression (found scanning real servers): a tools-only server answers "Method not
    # found" to resources/templates/list (optional in the MCP spec). The resource-scan pass
    # the CLI runs must tolerate that, not abort the whole scan. Exercises the real stdio +
    # ResourceToolView path that crashed on sequential-thinking/filesystem/github.
    async with stdio_session([sys.executable, _TOOLS_ONLY_SERVER]) as session:
        tool_scan = await scan_session(session, oob=None, transport="stdio")
        res_scan = await scan_session(ResourceToolView(session), oob=None, transport="stdio",
                                      check_ids=["path_traversal", "info_leak"])
    assert tool_scan.tools_discovered == 1       # the echo tool
    assert res_scan.tools_discovered == 0        # no resource templates -> [], not a crash


# --- passive lens + reachability wiring (net-new in v0.4) ---

class DeadBackendCodeSession:
    """Declares a dangerous execute_code tool; every call_tool raises (backend down)."""
    async def list_tools(self):
        return [ToolInfo("execute_code", "Execute IronPython code directly in Revit context.",
                {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]})]
    async def call_tool(self, name, args):
        raise ConnectionError("All connection attempts failed")


class HealthySession:
    async def list_tools(self):
        return [ToolInfo("read_doc", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})]
    async def call_tool(self, name, args):
        return "ok"


@pytest.mark.asyncio
async def test_passive_capability_flagged_without_live_backend():
    # The passive lens is manifest-only: it must surface the declared RCE tool even
    # though every tool call fails. This is the exact false-negative the feature fixes.
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio")
    caps = [f for f in findings if f.check == "capability"]
    assert any(f.severity.value == "critical" and f.param == "code-exec" for f in caps)


@pytest.mark.asyncio
async def test_reachability_note_emitted_when_backend_down():
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio")
    assert any(f.check == "reachability" and f.severity.value == "info" for f in findings)


@pytest.mark.asyncio
async def test_no_reachability_note_when_backend_healthy():
    findings = await scan_session(HealthySession(), oob=None, transport="stdio")
    assert not any(f.check == "reachability" for f in findings)


@pytest.mark.asyncio
async def test_reachability_suppressed_when_check_ids_restricted():
    # A restricted scan (e.g. the resource-only second pass) must not duplicate the note.
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio",
                                  check_ids=["path_traversal"])
    assert not any(f.check == "reachability" for f in findings)


# --- Gap 7: unauthenticated privileged proxy note (consumes the capability lens) ---

@pytest.mark.asyncio
async def test_privileged_proxy_note_on_unauthenticated_code_exec_stdio():
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio")
    notes = [f for f in findings if f.check == "privileged_proxy"]
    assert len(notes) == 1
    assert notes[0].severity.value == "info"
    assert "execute_code:code-exec" in notes[0].evidence   # names the privileged capability


@pytest.mark.asyncio
async def test_no_privileged_proxy_note_when_authenticated_http():
    # An authenticated scan (call_tool_unauth set => the CLI opened a --header session) is not
    # an unauthenticated surface, so no note even with a declared privileged capability.
    async def unauth(name, args):
        return "x"
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="http",
                                  call_tool_unauth=unauth)
    assert not any(f.check == "privileged_proxy" for f in findings)


@pytest.mark.asyncio
async def test_no_privileged_proxy_note_on_benign_server():
    findings = await scan_session(HealthySession(), oob=None, transport="stdio")
    assert not any(f.check == "privileged_proxy" for f in findings)


@pytest.mark.asyncio
async def test_privileged_proxy_suppressed_when_check_ids_restricted():
    findings = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio",
                                  check_ids=["capability"])
    assert not any(f.check == "privileged_proxy" for f in findings)


# --- Gap 3: active code-injection confirmation against a real eval sink ---

_CODE_SERVER = str(Path(__file__).parent / "fixtures" / "code_server" / "server.py")


@pytest.mark.asyncio
async def test_scan_confirms_code_injection_via_real_oob():
    # A language-native payload really opens a socket to the local OOB listener from
    # inside the eval sink - a genuine out-of-band proof of code execution, no Revit needed.
    # This is the "flag -> confirm" step: capability only flags execute-code tools.
    from mcpsnare.oob.local import LocalOOB
    with LocalOOB() as oob:
        async with stdio_session([sys.executable, _CODE_SERVER]) as session:
            findings = await scan_session(session, oob=oob, transport="stdio",
                                          check_ids=["code_injection"],
                                          oob_poll_interval=0.1, oob_timeout=2.0)
    confirmed = [f for f in findings
                 if f.check == "code_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1                     # deduped to one finding for (tool, param)
    assert confirmed[0].cwe == "CWE-94" and confirmed[0].param == "code"


@pytest.mark.asyncio
async def test_scan_code_injection_arithmetic_canary_firm_without_oob():
    # No OOB reachable: the arithmetic canary (7*7 -> 49, reflected, absent from the benign
    # baseline) still earns a FIRM finding.
    async with stdio_session([sys.executable, _CODE_SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["code_injection"])
    firm = [f for f in findings if f.check == "code_injection" and f.confidence.value == "firm"]
    assert len(firm) == 1                                     # the marker-reflected canary is the oracle
    assert firm[0].cwe == "CWE-94"
    assert "mcpsnareCANARY" in firm[0].payload               # the firing probe is a canary probe (not OOB/time)


@pytest.mark.asyncio
async def test_engine_dedup_upgrades_weaker_finding_to_stronger():
    # A deferred OOB CONFIRMED must UPGRADE an inline FIRM for the same (check, tool, param);
    # first-write-wins would wrongly keep the weaker FIRM.
    from mcpsnare.models import Probe, Finding, Severity, Confidence
    from mcpsnare.checks.base import REGISTRY

    class UpgradeSpy:
        id = "upgrade_spy"
        def generate(self, point, ctx):
            inline = Probe(check=self.id, point=point, payload="inline", args=point.set("x"))
            oobp = Probe(check=self.id, point=point, payload="oob", args=point.set("y"), token="tok")
            return [inline, oobp]                      # one inline (FIRM), one deferred OOB (CONFIRMED)
        def evaluate(self, probe, response, ctx):
            conf = Confidence.CONFIRMED if probe.token else Confidence.FIRM
            return Finding(self.id, probe.point.tool, probe.point.param_name, Severity.HIGH,
                           conf, "CWE-0", "t", probe.payload, "e", "r")

    class HitOOB:
        def new_token(self):
            return ("tok", "http://oob/tok")
        def interactions(self, t):
            return [{"path": "/tok"}] if t == "tok" else []
        def poll_all(self):
            return {"tok": [{"path": "/tok"}]}

    REGISTRY["upgrade_spy"] = UpgradeSpy()
    try:
        findings = await scan_session(FakeSession(), oob=HitOOB(), transport="stdio",
                                      check_ids=["upgrade_spy"], oob_poll_interval=0.001, oob_timeout=0.05)
    finally:
        del REGISTRY["upgrade_spy"]
    spy = [f for f in findings if f.check == "upgrade_spy"]
    assert len(spy) == 1 and spy[0].confidence.value == "confirmed"   # FIRM upgraded, not kept


@pytest.mark.asyncio
async def test_scan_no_code_injection_on_noncode_params():
    # code_injection must stay silent on a server with no code-ish param (vuln_server's
    # host/path/user/mode) - it gates on the parameter name.
    async with stdio_session([sys.executable, _SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio")
    assert not any(f.check == "code_injection" for f in findings)


# --- Gap 6: ScanResult scan metadata ---

@pytest.mark.asyncio
async def test_scan_session_returns_scan_metadata():
    from mcpsnare.models import ScanResult
    result = await scan_session(FakeSession(), oob=None, transport="stdio", target="python s.py")
    assert isinstance(result, ScanResult)
    assert result.target == "python s.py"
    assert result.transport == "stdio"
    assert result.tools_discovered == 1
    assert result.tools_reachable == 1                 # read_doc's benign call returns "ok"
    assert "path_traversal" in result.checks_executed  # active checks listed
    assert "capability" in result.checks_executed      # passive checks listed too
    assert result.aggressive is False


@pytest.mark.asyncio
async def test_scan_metadata_time_based_skipped_counts_points_in_default_mode():
    # FakeSession has one string injection point (read_doc.path); cmd/sql/code_injection
    # are time-based-capable, so a default scan reports it as skipped-by-time-based.
    default = await scan_session(FakeSession(), oob=None, transport="stdio")
    assert default.time_based_skipped == 1
    aggr = await scan_session(FakeSession(), oob=None, transport="stdio", aggressive=True)
    assert aggr.time_based_skipped == 0


@pytest.mark.asyncio
async def test_scan_metadata_time_based_skipped_for_cmd_or_sql_only_scan():
    # Each time-based-capable check must be counted on its own, not only when code_injection
    # happens to be in the default set (regression: only code_injection had time_based=True).
    for cid in ("cmd_injection", "sql_injection", "code_injection"):
        default = await scan_session(FakeSession(), oob=None, transport="stdio", check_ids=[cid])
        assert default.time_based_skipped == 1, cid


@pytest.mark.asyncio
async def test_scan_metadata_reachable_zero_when_backend_down():
    result = await scan_session(DeadBackendCodeSession(), oob=None, transport="stdio")
    assert result.tools_discovered == 1
    assert result.tools_reachable == 0                 # every benign call errored


# --- Gap 4: free-form dict container reached via a synthesized canary key ---

class FreeFormDictSession:
    """modify_element(parameters: dict[str,str]) - a free-form map whose values are funneled
    into a path-traversal sink. Before Gap 4 the mapper emitted zero injection points here."""
    async def list_tools(self):
        return [ToolInfo("modify_element", "", {"type": "object",
                "properties": {"parameters": {"type": "object",
                                              "additionalProperties": {"type": "string"}}},
                "required": ["parameters"]})]
    async def call_tool(self, name, args):
        params = args.get("parameters") or {}
        if any("etc/passwd" in str(v) for v in params.values()):
            return "root:x:0:0:root:/root:/bin/bash"
        return "ok"


@pytest.mark.asyncio
async def test_engine_probes_free_form_dict_via_synthesized_key():
    findings = await scan_session(FreeFormDictSession(), oob=None, transport="stdio",
                                  check_ids=["path_traversal"])
    confirmed = [f for f in findings
                 if f.check == "path_traversal" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].param == "parameters.mcpsnare"   # the synthesized open-map key


@pytest.mark.asyncio
async def test_scan_results_merge_via_add():
    from mcpsnare.connect.resources import ResourceToolView
    tool_scan = await scan_session(FakeSession(), oob=None, transport="stdio", target="python s.py")
    res_scan = await scan_session(ResourceToolView(FakeResourceSession()), oob=None,
                                  transport="stdio", check_ids=["path_traversal", "info_leak"])
    merged = tool_scan + res_scan
    assert merged.target == "python s.py"
    assert merged.tools_discovered == tool_scan.tools_discovered + res_scan.tools_discovered
    assert set(merged.checks_executed) >= {"path_traversal", "info_leak"}
    assert len(merged) == len(tool_scan) + len(res_scan)
