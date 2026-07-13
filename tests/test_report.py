import json
from mcpsnare.models import Finding, ScanResult, Severity, Confidence
from mcpsnare.report.render import to_json, to_sarif, to_markdown

def _f():
    return [Finding("cmd_injection", "ping", "host", Severity.CRITICAL, Confidence.CONFIRMED,
                    "CWE-78", "Command injection in ping.host", "; sleep 5", "oob hit", "no shell")]


def _result():
    return ScanResult(findings=_f(), target="python vuln.py", transport="stdio",
                      tools_discovered=6, tools_reachable=6,
                      checks_executed=["cmd_injection", "path_traversal"],
                      aggressive=False, time_based_skipped=6)


def test_json_report_structure():
    data = json.loads(to_json(_f()))
    assert data["summary"]["critical"] == 1
    assert data["findings"][0]["cwe"] == "CWE-78"

def test_sarif_is_valid_json_with_rules():
    s = json.loads(to_sarif(_f()))
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["results"][0]["ruleId"] == "cmd_injection"

def test_markdown_contains_title_and_severity():
    md = to_markdown(_f())
    assert "Command injection in ping.host" in md and "CRITICAL" in md


# --- Gap 6: scan metadata in reports (ScanResult) ---

def test_json_includes_scan_metadata_for_scanresult():
    data = json.loads(to_json(_result()))
    assert data["scan"]["target"] == "python vuln.py"
    assert data["scan"]["transport"] == "stdio"
    assert data["scan"]["tools_discovered"] == 6 and data["scan"]["tools_reachable"] == 6
    assert data["scan"]["checks_executed"] == ["cmd_injection", "path_traversal"]
    assert data["scan"]["aggressive"] is False
    assert data["scan"]["time_based_skipped"] == 6
    assert data["scan"]["notes"]                     # honesty note present in default mode
    assert data["summary"]["critical"] == 1          # findings still rendered
    assert data["findings"][0]["cwe"] == "CWE-78"


def test_json_no_scan_block_for_plain_list_back_compat():
    data = json.loads(to_json(_f()))
    assert "scan" not in data and data["summary"]["critical"] == 1


def test_sarif_includes_invocation_properties_for_scanresult():
    s = json.loads(to_sarif(_result()))
    inv = s["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["properties"]["tools_discovered"] == 6
    assert s["runs"][0]["results"][0]["ruleId"] == "cmd_injection"


def test_sarif_no_invocations_for_plain_list_back_compat():
    s = json.loads(to_sarif(_f()))
    assert "invocations" not in s["runs"][0]


def test_markdown_includes_scan_metadata_section():
    md = to_markdown(_result())
    assert "Scan metadata" in md and "python vuln.py" in md
    assert "Command injection in ping.host" in md    # findings still present
