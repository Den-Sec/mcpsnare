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
