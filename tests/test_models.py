from mcprobe.models import Severity, Confidence, ToolInfo, InjectionPoint, Probe, Finding


def test_finding_roundtrip():
    p = InjectionPoint(tool="ping", json_path="host", base_args={"host": "x"}, param_name="host")
    pr = Probe(check="cmd_injection", point=p, payload="; id", args={"host": "x; id"})
    f = Finding(check="cmd_injection", tool="ping", param="host",
                severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                cwe="CWE-78", title="Command injection in ping.host",
                payload="; id", evidence="oob hit", remediation="no shell")
    assert f.severity == Severity.CRITICAL
    assert pr.point.param_name == "host"
    assert ToolInfo(name="ping", description="", input_schema={}).name == "ping"


def test_injection_point_set_top_level():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="host", base_args={"host": "mcprobe"}, param_name="host")
    assert p.set("X") == {"host": "X"}


def test_injection_point_set_nested_preserves_siblings():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="config.path",
                       base_args={"config": {"path": "mcprobe", "mode": "safe"}},
                       param_name="config.path")
    assert p.set("X") == {"config": {"path": "X", "mode": "safe"}}


def test_injection_point_set_does_not_mutate_base_args():
    from mcprobe.models import InjectionPoint
    base = {"config": {"path": "mcprobe"}}
    p = InjectionPoint(tool="t", json_path="config.path", base_args=base, param_name="config.path")
    p.set("X")
    assert base == {"config": {"path": "mcprobe"}}  # unchanged - deep copy


def test_injection_point_set_array():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="paths[0]", base_args={"paths": ["mcprobe"]},
                       param_name="paths[0]")
    assert p.set("X") == {"paths": ["X"]}


def test_tool_baseline_holds_latency_and_response():
    from mcprobe.models import ToolBaseline
    b = ToolBaseline(latency=0.42, response="hello")
    assert b.latency == 0.42
    assert b.response == "hello"


def test_injection_point_embed_prefixes_valid_value():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="email",
                       base_args={"email": "probe@mcprobe.example"}, param_name="email")
    out = p.embed("; curl http://oob/x")
    assert out["email"] == "probe@mcprobe.example; curl http://oob/x"


def test_injection_point_embed_empty_when_leaf_absent():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="missing", base_args={}, param_name="missing")
    assert p.embed("PAY")["missing"] == "PAY"
