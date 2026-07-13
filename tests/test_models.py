from mcpsnare.models import Severity, Confidence, ToolInfo, InjectionPoint, Probe, Finding


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
    from mcpsnare.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="host", base_args={"host": "mcpsnare"}, param_name="host")
    assert p.set("X") == {"host": "X"}


def test_injection_point_set_nested_preserves_siblings():
    from mcpsnare.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="config.path",
                       base_args={"config": {"path": "mcpsnare", "mode": "safe"}},
                       param_name="config.path")
    assert p.set("X") == {"config": {"path": "X", "mode": "safe"}}


def test_injection_point_set_does_not_mutate_base_args():
    from mcpsnare.models import InjectionPoint
    base = {"config": {"path": "mcpsnare"}}
    p = InjectionPoint(tool="t", json_path="config.path", base_args=base, param_name="config.path")
    p.set("X")
    assert base == {"config": {"path": "mcpsnare"}}  # unchanged - deep copy


def test_injection_point_set_array():
    from mcpsnare.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="paths[0]", base_args={"paths": ["mcpsnare"]},
                       param_name="paths[0]")
    assert p.set("X") == {"paths": ["X"]}


def test_tool_baseline_holds_latency_and_response():
    from mcpsnare.models import ToolBaseline
    b = ToolBaseline(latency=0.42, response="hello")
    assert b.latency == 0.42
    assert b.response == "hello"


def test_injection_point_embed_prefixes_valid_value():
    from mcpsnare.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="email",
                       base_args={"email": "probe@mcpsnare.example"}, param_name="email")
    out = p.embed("; curl http://oob/x")
    assert out["email"] == "probe@mcpsnare.example; curl http://oob/x"


def test_injection_point_embed_empty_when_leaf_absent():
    from mcpsnare.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="missing", base_args={}, param_name="missing")
    assert p.embed("PAY")["missing"] == "PAY"


# --- Gap 6: ScanResult (findings + scan metadata, list-like for back-compat) ---

def _find(check="c", param="p", sev=None, conf=None):
    return Finding(check, "t", param, sev or Severity.INFO, conf or Confidence.TENTATIVE,
                   "", "T", "P", "E", "R")


def test_scan_result_is_list_like():
    from mcpsnare.models import ScanResult
    f = _find()
    r = ScanResult(findings=[f], target="python s.py", transport="stdio",
                   tools_discovered=3, tools_reachable=2, checks_executed=["cmd_injection"],
                   aggressive=True, time_based_skipped=0)
    assert len(r) == 1
    assert r[0] is f
    assert list(r) == [f]
    assert [x for x in r] == [f]


def test_scan_result_equals_list_for_back_compat():
    from mcpsnare.models import ScanResult
    assert ScanResult(findings=[]) == []
    f = _find()
    assert ScanResult(findings=[f]) == [f]
    assert (ScanResult(findings=[]) == [f]) is False


def test_scan_result_bool_reflects_findings():
    from mcpsnare.models import ScanResult
    assert not ScanResult(findings=[])
    assert ScanResult(findings=[_find()])


def test_scan_result_add_merges_metadata_and_findings():
    from mcpsnare.models import ScanResult
    f1, f2 = _find(check="cmd", param="host"), _find(check="path_traversal", param="path")
    a = ScanResult(findings=[f1], target="tgt", transport="stdio", tools_discovered=3,
                   tools_reachable=3, checks_executed=["cmd_injection", "ssrf"],
                   aggressive=False, time_based_skipped=3)
    b = ScanResult(findings=[f2], target="", transport="stdio", tools_discovered=1,
                   tools_reachable=1, checks_executed=["path_traversal", "info_leak"],
                   aggressive=True, time_based_skipped=1)
    m = a + b
    assert m.findings == [f1, f2]                 # concatenated
    assert m.target == "tgt" and m.transport == "stdio"   # non-empty preferred
    assert m.tools_discovered == 4 and m.tools_reachable == 4  # summed
    assert m.checks_executed == ["cmd_injection", "ssrf", "path_traversal", "info_leak"]  # union, ordered
    assert m.aggressive is True                   # OR
    assert m.time_based_skipped == 4              # summed


def test_scan_result_iadd_uses_add():
    from mcpsnare.models import ScanResult
    r = ScanResult(findings=[])
    r += ScanResult(findings=[_find()], tools_discovered=1)
    assert len(r) == 1 and r.tools_discovered == 1
