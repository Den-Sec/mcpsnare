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
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(), transport="stdio")
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
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.0
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"
