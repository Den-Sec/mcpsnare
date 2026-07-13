from mcpsnare.models import InjectionPoint
from mcpsnare.checks.base import CheckContext, register, REGISTRY


def test_register_adds_to_registry():
    @register
    class Dummy:
        id = "dummy"
        def generate(self, point, ctx): return []
        def evaluate(self, probe, response, ctx): return None
    assert "dummy" in REGISTRY
    assert REGISTRY["dummy"].id == "dummy"

def test_context_holds_callables():
    ctx = CheckContext(call_tool=lambda n, a: "resp", oob=None, transport="stdio")
    assert ctx.call_tool("x", {}) == "resp"
    assert ctx.transport == "stdio"


# --- Task 6: path_traversal ---
from mcpsnare.checks.path_traversal import PathTraversal


def _ctx(): return CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")

def test_traversal_generates_payloads():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcpsnare"}, "path")
    probes = pt.generate(point, _ctx())
    assert any("../" in p.payload for p in probes)
    assert all(p.args["path"] == p.payload for p in probes)

def test_traversal_confirmed_on_passwd_canary():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcpsnare"}, "path")
    probe = pt.generate(point, _ctx())[0]
    f = pt.evaluate(probe, "root:x:0:0:root:/root:/bin/bash\n", _ctx())
    assert f is not None and f.confidence.value == "confirmed" and f.cwe == "CWE-22"

def test_traversal_none_on_clean_response():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcpsnare"}, "path")
    probe = pt.generate(point, _ctx())[0]
    assert pt.evaluate(probe, "file not found", _ctx()) is None


# --- Task 7: info_leak ---
from mcpsnare.checks.info_leak import InfoLeak


def test_info_leak_needs_two_markers():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcpsnare"}, "q")
    probe = il.generate(point, _ctx())[0]
    one = "AKIAIOSFODNN7EXAMPLE"
    two = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    assert il.evaluate(probe, one, _ctx()) is None
    f = il.evaluate(probe, two, _ctx())
    assert f is not None and f.cwe == "CWE-200"


# --- Task 8: cmd_injection ---
from mcpsnare.checks.cmd_injection import CmdInjection

class FakeOOB:
    def __init__(self, hit_token=None): self.hit = hit_token
    def new_token(self): return ("tok123", "http://oob/tok123")
    def interactions(self, token): return [{"path": "/tok123"}] if token == self.hit else []

def test_cmdi_generates_oob_and_time_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(), transport="stdio", aggressive=True)
    point = InjectionPoint("ping", "host", {"host": "mcpsnare"}, "host")
    probes = c.generate(point, ctx)
    assert any("http://oob/tok123" in p.payload for p in probes)
    assert any("sleep" in p.payload for p in probes)
    assert all(p.token == "tok123" for p in probes if "oob" in p.payload)

def test_cmdi_confirmed_on_oob_hit():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(hit_token="tok123"), transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcpsnare"}, "host")
    oob_probe = [p for p in c.generate(point, ctx) if p.token][0]
    f = c.evaluate(oob_probe, "", ctx)
    assert f is not None and f.confidence.value == "confirmed" and f.cwe == "CWE-78"

def test_cmdi_firm_on_time_delay():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("ping", "host", {"host": "mcpsnare"}, "host")
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.0
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"


def test_cmdi_default_omits_blocking_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # aggressive=False
    point = InjectionPoint("run", "host", {"host": "mcpsnare"}, "host")
    probes = c.generate(point, ctx)
    assert all(not p.meta.get("time_based") for p in probes)
    assert all("sleep" not in p.payload for p in probes)


def test_cmdi_aggressive_enables_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcpsnare"}, "host")
    probes = c.generate(point, ctx)
    assert any(p.meta.get("time_based") for p in probes)


# --- Task 9: ssrf ---
from mcpsnare.checks.ssrf import SSRF

def test_ssrf_injects_oob_url_and_confirms():
    s = SSRF()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(hit_token="tok123"), transport="http")
    point = InjectionPoint("fetch", "url", {"url": "mcpsnare"}, "url")
    probe = s.generate(point, ctx)[0]
    assert probe.args["url"].startswith("http://oob/")
    f = s.evaluate(probe, "", ctx)
    assert f is not None and f.cwe == "CWE-918" and f.confidence.value == "confirmed"

def test_ssrf_skipped_without_oob():
    s = SSRF()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="http")
    point = InjectionPoint("fetch", "url", {"url": "mcpsnare"}, "url")
    assert s.generate(point, ctx) == []


# --- Task 10: auth_bypass ---
from mcpsnare.checks.auth_bypass import AuthBypass

def test_auth_bypass_skipped_on_stdio_or_no_unauth():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    stdio = CheckContext(call_tool=lambda n, args: "ok", oob=None, transport="stdio")
    assert a.generate(point, stdio) == []

def test_auth_bypass_confirmed_when_unauth_succeeds():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    ctx = CheckContext(call_tool=lambda n, args: "secret data", oob=None, transport="http",
                       call_tool_unauth=lambda n, args: "secret data")
    probe = a.generate(point, ctx)[0]
    probe.meta["unauth_response"] = "secret data"
    f = a.evaluate(probe, "secret data", ctx)
    assert f is not None and f.cwe == "CWE-306" and f.confidence.value == "confirmed"

def test_auth_bypass_none_when_unauth_denied():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    def deny(n, args): raise PermissionError("401")
    ctx = CheckContext(call_tool=lambda n, args: "secret data", oob=None, transport="http",
                       call_tool_unauth=deny)
    probe = a.generate(point, ctx)[0]
    assert a.evaluate(probe, "secret data", ctx) is None


def test_auth_bypass_firm_when_only_timestamp_differs():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    auth_resp = '{"user":"root","ts":"2026-06-10T10:00:00Z","data":"secret"}'
    unauth_resp = '{"user":"root","ts":"2026-06-10T10:00:09Z","data":"secret"}'
    ctx = CheckContext(call_tool=lambda n, args: auth_resp, oob=None, transport="http",
                       call_tool_unauth=lambda n, args: unauth_resp)
    probe = a.generate(point, ctx)[0]
    probe.meta["unauth_response"] = unauth_resp
    f = a.evaluate(probe, auth_resp, ctx)
    assert f is not None and f.cwe == "CWE-306" and f.confidence.value == "firm"


def test_auth_bypass_none_when_unauth_substantively_differs():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    ctx = CheckContext(call_tool=lambda n, args: '{"data":"secret"}', oob=None, transport="http",
                       call_tool_unauth=lambda n, args: '{"error":"401 unauthorized"}')
    probe = a.generate(point, ctx)[0]
    probe.meta["unauth_response"] = '{"error":"401 unauthorized"}'
    assert a.evaluate(probe, '{"data":"secret"}', ctx) is None


def test_auth_bypass_none_when_only_record_id_differs():
    # Different records (different 'id' value) must NOT be treated as a bypass.
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcpsnare"}, "x")
    auth_resp = '{"id":"user-1001","name":"alice","role":"viewer"}'
    unauth_resp = '{"id":"user-9999","name":"alice","role":"viewer"}'
    ctx = CheckContext(call_tool=lambda n, args: auth_resp, oob=None, transport="http",
                       call_tool_unauth=lambda n, args: unauth_resp)
    probe = a.generate(point, ctx)[0]
    probe.meta["unauth_response"] = unauth_resp
    assert a.evaluate(probe, auth_resp, ctx) is None


def test_path_traversal_deep_sets_nested_path():
    from mcpsnare.checks.path_traversal import PathTraversal
    from mcpsnare.models import InjectionPoint
    pt = PathTraversal()
    point = InjectionPoint("read_cfg", "config.path",
                           {"config": {"path": "mcpsnare"}}, "config.path")
    probe = pt.generate(point, _ctx())[0]
    assert probe.args == {"config": {"path": probe.payload}}


# --- Task 11: all checks registered ---
def test_all_v1_checks_registered():
    import mcpsnare.checks
    from mcpsnare.checks.base import REGISTRY
    assert {"path_traversal", "info_leak", "cmd_injection", "ssrf", "auth_bypass",
            "sql_injection"} <= set(REGISTRY)


def test_check_context_baseline_defaults_none_and_accepts_value():
    from mcpsnare.checks.base import CheckContext
    from mcpsnare.models import ToolBaseline
    ctx = CheckContext(oob=None, transport="stdio")
    assert ctx.baseline is None
    ctx2 = CheckContext(oob=None, transport="stdio", baseline=ToolBaseline(latency=1.0, response="r"))
    assert ctx2.baseline.latency == 1.0


def _ctx_with_baseline(latency, response=""):
    from mcpsnare.checks.base import CheckContext
    from mcpsnare.models import ToolBaseline
    return CheckContext(oob=None, transport="stdio", aggressive=True,
                        baseline=ToolBaseline(latency=latency, response=response))


def test_cmdi_no_time_fp_on_slow_safe_tool():
    c = CmdInjection()
    point = InjectionPoint("slow", "host", {"host": "mcpsnare"}, "host")
    ctx = _ctx_with_baseline(6.0)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.1
    assert c.evaluate(time_probe, "", ctx) is None


def test_cmdi_firm_when_delay_exceeds_baseline_margin():
    c = CmdInjection()
    point = InjectionPoint("ping", "host", {"host": "mcpsnare"}, "host")
    ctx = _ctx_with_baseline(0.1)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 5.1
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"


def test_info_leak_suppressed_when_secret_in_baseline():
    il = InfoLeak()
    point = InjectionPoint("docs", "q", {"q": "mcpsnare"}, "q")
    secrets = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    ctx = _ctx_with_baseline(0.1, response=secrets)
    probe = il.generate(point, ctx)[0]
    assert il.evaluate(probe, secrets, ctx) is None


def test_info_leak_firm_on_triggered_diff():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcpsnare"}, "q")
    ctx = _ctx_with_baseline(0.1, response="nothing secret here")
    probe = il.generate(point, ctx)[0]
    leaked = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    f = il.evaluate(probe, leaked, ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-200"


def test_info_leak_tentative_pattern_only_without_baseline():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcpsnare"}, "q")
    two = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    f = il.evaluate(il.generate(point, _ctx())[0], two, _ctx())
    assert f is not None and f.confidence.value == "tentative"


class PerPayloadOOB:
    """Issues a DISTINCT token per new_token() call; only the chosen token 'fires'."""
    def __init__(self):
        self._n = 0
        self.fired = None  # set to the token whose callback should resolve
    def new_token(self):
        self._n += 1
        t = f"tok{self._n}"
        return t, f"http://oob/{t}"
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token == self.fired else []


def test_cmdi_per_payload_tokens_identify_separator():
    c = CmdInjection()
    oob = PerPayloadOOB()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=oob, transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcpsnare"}, "host")
    oob_probes = [p for p in c.generate(point, ctx) if p.token]
    assert len({p.token for p in oob_probes}) == len(oob_probes)
    assert len(oob_probes) >= 6
    amp = [p for p in oob_probes if p.payload.startswith("mcpsnare& curl")][0]
    oob.fired = amp.token
    confirmed = [c.evaluate(p, "", ctx) for p in oob_probes]
    confirmed = [f for f in confirmed if f]
    assert len(confirmed) == 1
    assert confirmed[0].payload == amp.payload
    assert "& curl" in confirmed[0].evidence


def test_cmdi_oob_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    point = InjectionPoint("run", "host", {"host": "mcpsnare"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "$(curl" in blob        # POSIX command substitution
    assert "| curl" in blob        # cmd.exe / POSIX pipe
    assert "iwr " in blob          # PowerShell Invoke-WebRequest
    assert "curl.exe " in blob     # PowerShell real curl


def test_cmdi_sleep_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcpsnare"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "sleep 5" in blob              # POSIX
    assert "Start-Sleep -s 5" in blob     # PowerShell
    assert "ping -n 6" in blob            # cmd.exe (no sleep builtin)


def test_cmdi_emits_embed_variant_for_formatted_param():
    c = CmdInjection()
    oob = PerPayloadOOB()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=oob, transport="stdio")
    point = InjectionPoint("send", "to", {"to": "probe@mcpsnare.example"}, "to")
    payloads = [p.payload for p in c.generate(point, ctx)]
    assert any(p.startswith("probe@mcpsnare.example") and "curl" in p for p in payloads)


# --- M7-T1: sql_injection ---
from mcpsnare.checks.sql_injection import SqlInjection


def test_sqli_firm_on_error_signature_diff():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcpsnare"}, "name")
    ctx = _ctx_with_baseline(0.1, response="ok normal output")
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    f = s.evaluate(probe, "ERROR: near \"'\": syntax error", ctx)
    assert f is not None and f.cwe == "CWE-89" and f.confidence.value == "firm"


def test_sqli_suppressed_when_error_in_baseline():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcpsnare"}, "name")
    ctx = _ctx_with_baseline(0.1, response="SQL syntax error appears even on benign input")
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    assert s.evaluate(probe, "you have an error in your SQL syntax", ctx) is None


def test_sqli_tentative_error_without_baseline():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcpsnare"}, "name")
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # no baseline
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    f = s.evaluate(probe, "Warning: mysql_fetch_array() expects", ctx)
    assert f is not None and f.confidence.value == "tentative"


def test_sqli_time_based_only_when_aggressive():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcpsnare"}, "name")
    default = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")
    assert all(not p.meta.get("time_based") for p in s.generate(point, default))
    aggr = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    assert any(p.meta.get("time_based") for p in s.generate(point, aggr))


def test_sqli_time_based_firm_on_calibrated_delay():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcpsnare"}, "name")
    ctx = _ctx_with_baseline(0.1)  # aggressive=True via helper
    tprobe = [p for p in s.generate(point, ctx) if p.meta.get("time_based")][0]
    tprobe.meta["elapsed"] = 5.1
    f = s.evaluate(tprobe, "", ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-89"


# --- Gap 3: code_injection (CWE-94) ---
from mcpsnare.checks.code_injection import CodeInjection


def _code_pt(name="code", tool="run_code"):
    return InjectionPoint(tool, name, {name: "mcpsnare"}, name)


def test_codei_gates_on_code_param_name():
    c = CodeInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    assert c.generate(_code_pt("code"), ctx)                       # code-ish -> probes
    assert c.generate(_code_pt("name", tool="greet"), ctx) == []   # non-code -> none


def test_codei_gate_matches_code_params_and_skips_others():
    c = CodeInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    for name in ["code", "script", "scripts", "expression", "python_code",
                 "ironpython", "snippet", "formula", "evalExpr", "config.code"]:
        pt = InjectionPoint("t", name, {}, name)
        assert c.generate(pt, ctx), name
    for name in ["query", "name", "barcode", "host", "path", "mode"]:
        pt = InjectionPoint("t", name, {}, name)
        assert c.generate(pt, ctx) == [], name


def test_codei_generates_language_native_oob_payloads_with_distinct_tokens():
    c = CodeInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    oob_probes = [p for p in c.generate(_code_pt(), ctx) if p.token]
    blob = " ".join(p.payload for p in oob_probes)
    assert "urllib" in blob and "urllib2" in blob and "urlopen" in blob  # py3 + py2/ironpython
    assert "require('http')" in blob                                     # node eval sink
    assert len({p.token for p in oob_probes}) == len(oob_probes)         # per-payload tokens


def test_codei_confirmed_on_oob_hit():
    c = CodeInjection()
    oob = PerPayloadOOB()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=oob, transport="stdio")
    oob_probes = [p for p in c.generate(_code_pt(), ctx) if p.token]
    oob.fired = oob_probes[0].token
    f = c.evaluate(oob_probes[0], "", ctx)
    assert f is not None and f.confidence.value == "confirmed"
    assert f.cwe == "CWE-94" and f.severity.value == "critical" and f.param == "code"


def test_codei_firm_on_arithmetic_canary_baseline_diff():
    c = CodeInjection()
    ctx = _ctx_with_baseline(0.1, response="error: name 'mcpsnare' is not defined")
    canary = [p for p in c.generate(_code_pt(), ctx) if p.meta.get("canary")][0]
    f = c.evaluate(canary, "mcpsnareCANARY49", ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-94"


def test_codei_tentative_canary_without_baseline():
    c = CodeInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # no baseline
    canary = [p for p in c.generate(_code_pt(), ctx) if p.meta.get("canary")][0]
    f = c.evaluate(canary, "result: mcpsnareCANARY49", ctx)
    assert f is not None and f.confidence.value == "tentative"


def test_codei_canary_suppressed_when_marker_in_baseline():
    c = CodeInjection()
    ctx = _ctx_with_baseline(0.1, response="mcpsnareCANARY49 already present")
    canary = [p for p in c.generate(_code_pt(), ctx) if p.meta.get("canary")][0]
    assert c.evaluate(canary, "mcpsnareCANARY49", ctx) is None


def test_codei_no_finding_on_clean_response():
    c = CodeInjection()
    ctx = _ctx_with_baseline(0.1, response="ok")
    for p in c.generate(_code_pt(), ctx):
        if not p.meta.get("time_based"):
            assert c.evaluate(p, "totally benign output", ctx) is None


def test_codei_default_omits_time_based_probes():
    c = CodeInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # not aggressive
    probes = c.generate(_code_pt(), ctx)
    assert probes and all(not p.meta.get("time_based") for p in probes)


def test_codei_aggressive_enables_time_based_firm():
    c = CodeInjection()
    ctx = _ctx_with_baseline(0.1)  # aggressive=True via helper
    tprobe = [p for p in c.generate(_code_pt(), ctx) if p.meta.get("time_based")][0]
    tprobe.meta["elapsed"] = 5.1
    f = c.evaluate(tprobe, "", ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-94"


def test_codei_registered():
    import mcpsnare.checks  # noqa: F401
    from mcpsnare.checks.base import REGISTRY
    assert "code_injection" in REGISTRY
