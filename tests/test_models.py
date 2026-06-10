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
