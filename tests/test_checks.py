from mcprobe.models import InjectionPoint
from mcprobe.checks.base import CheckContext, register, REGISTRY


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
from mcprobe.checks.path_traversal import PathTraversal


def _ctx(): return CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")

def test_traversal_generates_payloads():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probes = pt.generate(point, _ctx())
    assert any("../" in p.payload for p in probes)
    assert all(p.args["path"] == p.payload for p in probes)

def test_traversal_confirmed_on_passwd_canary():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probe = pt.generate(point, _ctx())[0]
    f = pt.evaluate(probe, "root:x:0:0:root:/root:/bin/bash\n", _ctx())
    assert f is not None and f.confidence.value == "confirmed" and f.cwe == "CWE-22"

def test_traversal_none_on_clean_response():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probe = pt.generate(point, _ctx())[0]
    assert pt.evaluate(probe, "file not found", _ctx()) is None


# --- Task 7: info_leak ---
from mcprobe.checks.info_leak import InfoLeak


def test_info_leak_needs_two_markers():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcprobe"}, "q")
    probe = il.generate(point, _ctx())[0]
    one = "AKIAIOSFODNN7EXAMPLE"
    two = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    assert il.evaluate(probe, one, _ctx()) is None
    f = il.evaluate(probe, two, _ctx())
    assert f is not None and f.cwe == "CWE-200"


# --- Task 8: cmd_injection ---
from mcprobe.checks.cmd_injection import CmdInjection

class FakeOOB:
    def __init__(self, hit_token=None): self.hit = hit_token
    def new_token(self): return ("tok123", "http://oob/tok123")
    def interactions(self, token): return [{"path": "/tok123"}] if token == self.hit else []

def test_cmdi_generates_oob_and_time_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(), transport="stdio", aggressive=True)
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    probes = c.generate(point, ctx)
    assert any("http://oob/tok123" in p.payload for p in probes)
    assert any("sleep" in p.payload for p in probes)
    assert all(p.token == "tok123" for p in probes if "oob" in p.payload)

def test_cmdi_confirmed_on_oob_hit():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(hit_token="tok123"), transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    oob_probe = [p for p in c.generate(point, ctx) if p.token][0]
    f = c.evaluate(oob_probe, "", ctx)
    assert f is not None and f.confidence.value == "confirmed" and f.cwe == "CWE-78"

def test_cmdi_firm_on_time_delay():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.0
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"


def test_cmdi_default_omits_blocking_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # aggressive=False
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    probes = c.generate(point, ctx)
    assert all(not p.meta.get("time_based") for p in probes)
    assert all("sleep" not in p.payload for p in probes)


def test_cmdi_aggressive_enables_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    probes = c.generate(point, ctx)
    assert any(p.meta.get("time_based") for p in probes)


# --- Task 9: ssrf ---
from mcprobe.checks.ssrf import SSRF

def test_ssrf_injects_oob_url_and_confirms():
    s = SSRF()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(hit_token="tok123"), transport="http")
    point = InjectionPoint("fetch", "url", {"url": "mcprobe"}, "url")
    probe = s.generate(point, ctx)[0]
    assert probe.args["url"].startswith("http://oob/")
    f = s.evaluate(probe, "", ctx)
    assert f is not None and f.cwe == "CWE-918" and f.confidence.value == "confirmed"

def test_ssrf_skipped_without_oob():
    s = SSRF()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="http")
    point = InjectionPoint("fetch", "url", {"url": "mcprobe"}, "url")
    assert s.generate(point, ctx) == []


# --- Task 10: auth_bypass ---
from mcprobe.checks.auth_bypass import AuthBypass

def test_auth_bypass_skipped_on_stdio_or_no_unauth():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcprobe"}, "x")
    stdio = CheckContext(call_tool=lambda n, args: "ok", oob=None, transport="stdio")
    assert a.generate(point, stdio) == []

def test_auth_bypass_confirmed_when_unauth_succeeds():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcprobe"}, "x")
    ctx = CheckContext(call_tool=lambda n, args: "secret data", oob=None, transport="http",
                       call_tool_unauth=lambda n, args: "secret data")
    probe = a.generate(point, ctx)[0]
    f = a.evaluate(probe, "secret data", ctx)
    assert f is not None and f.cwe == "CWE-306"

def test_auth_bypass_none_when_unauth_denied():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcprobe"}, "x")
    def deny(n, args): raise PermissionError("401")
    ctx = CheckContext(call_tool=lambda n, args: "secret data", oob=None, transport="http",
                       call_tool_unauth=deny)
    probe = a.generate(point, ctx)[0]
    assert a.evaluate(probe, "secret data", ctx) is None


def test_path_traversal_deep_sets_nested_path():
    from mcprobe.checks.path_traversal import PathTraversal
    from mcprobe.models import InjectionPoint
    pt = PathTraversal()
    point = InjectionPoint("read_cfg", "config.path",
                           {"config": {"path": "mcprobe"}}, "config.path")
    probe = pt.generate(point, _ctx())[0]
    assert probe.args == {"config": {"path": probe.payload}}


# --- Task 11: all checks registered ---
def test_all_v1_checks_registered():
    import mcprobe.checks
    from mcprobe.checks.base import REGISTRY
    assert {"path_traversal", "info_leak", "cmd_injection", "ssrf", "auth_bypass"} <= set(REGISTRY)


def test_check_context_baseline_defaults_none_and_accepts_value():
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    ctx = CheckContext(oob=None, transport="stdio")
    assert ctx.baseline is None
    ctx2 = CheckContext(oob=None, transport="stdio", baseline=ToolBaseline(latency=1.0, response="r"))
    assert ctx2.baseline.latency == 1.0


def _ctx_with_baseline(latency, response=""):
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    return CheckContext(oob=None, transport="stdio", aggressive=True,
                        baseline=ToolBaseline(latency=latency, response=response))


def test_cmdi_no_time_fp_on_slow_safe_tool():
    c = CmdInjection()
    point = InjectionPoint("slow", "host", {"host": "mcprobe"}, "host")
    ctx = _ctx_with_baseline(6.0)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.1
    assert c.evaluate(time_probe, "", ctx) is None


def test_cmdi_firm_when_delay_exceeds_baseline_margin():
    c = CmdInjection()
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    ctx = _ctx_with_baseline(0.1)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 5.1
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"


def test_info_leak_suppressed_when_secret_in_baseline():
    il = InfoLeak()
    point = InjectionPoint("docs", "q", {"q": "mcprobe"}, "q")
    secrets = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    ctx = _ctx_with_baseline(0.1, response=secrets)
    probe = il.generate(point, ctx)[0]
    assert il.evaluate(probe, secrets, ctx) is None


def test_info_leak_firm_on_triggered_diff():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcprobe"}, "q")
    ctx = _ctx_with_baseline(0.1, response="nothing secret here")
    probe = il.generate(point, ctx)[0]
    leaked = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    f = il.evaluate(probe, leaked, ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-200"


def test_info_leak_tentative_pattern_only_without_baseline():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcprobe"}, "q")
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
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    oob_probes = [p for p in c.generate(point, ctx) if p.token]
    assert len({p.token for p in oob_probes}) == len(oob_probes)
    assert len(oob_probes) >= 6
    amp = [p for p in oob_probes if p.payload.startswith("mcprobe& curl")][0]
    oob.fired = amp.token
    confirmed = [c.evaluate(p, "", ctx) for p in oob_probes]
    confirmed = [f for f in confirmed if f]
    assert len(confirmed) == 1
    assert confirmed[0].payload == amp.payload
    assert "& curl" in confirmed[0].evidence


def test_cmdi_oob_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "$(curl" in blob        # POSIX command substitution
    assert "| curl" in blob        # cmd.exe / POSIX pipe
    assert "iwr " in blob          # PowerShell Invoke-WebRequest
    assert "curl.exe " in blob     # PowerShell real curl


def test_cmdi_sleep_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "sleep 5" in blob              # POSIX
    assert "Start-Sleep -s 5" in blob     # PowerShell
    assert "ping -n 6" in blob            # cmd.exe (no sleep builtin)
