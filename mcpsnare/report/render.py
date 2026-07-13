import json
from collections import Counter
from mcpsnare.models import Finding, ScanResult

def _summary(findings):
    c = Counter(f.severity.value for f in findings)
    return {s: c.get(s, 0) for s in ("critical", "high", "medium", "low", "info")}

def _split(arg):
    """Accept either a rich ScanResult or a bare ``list[Finding]`` (back-compat).

    Returns ``(scan_or_None, findings_list)`` - when the caller passed a plain list the
    reports omit the scan-metadata block, exactly as before ScanResult existed."""
    if isinstance(arg, ScanResult):
        return arg, list(arg.findings)
    return None, list(arg)

def _scan_notes(scan):
    """Honesty notes derived from the metadata (mirrors the CLI's stderr note): a clean
    report is not a clean bill of health if blocking probes were skipped or nothing replied."""
    notes = []
    if not scan.aggressive and scan.time_based_skipped:
        notes.append(
            f"Default mode: {scan.time_based_skipped} injection point(s) were not exercised with "
            f"blocking time-based probes (re-run with --aggressive). An empty result is not proof "
            f"the target is secure.")
    if scan.tools_discovered and scan.tools_reachable == 0:
        notes.append(
            "No tool responded to a benign calibration call; active checks are inconclusive "
            "(see the reachability finding).")
    return notes

def _scan_meta(scan):
    return {
        "target": scan.target,
        "transport": scan.transport,
        "tools_discovered": scan.tools_discovered,
        "tools_reachable": scan.tools_reachable,
        "checks_executed": list(scan.checks_executed),
        "aggressive": scan.aggressive,
        "time_based_skipped": scan.time_based_skipped,
        "notes": _scan_notes(scan),
    }

def to_json(result) -> str:
    scan, findings = _split(result)
    doc = {}
    if scan is not None:
        doc["scan"] = _scan_meta(scan)
    doc["summary"] = _summary(findings)
    doc["findings"] = [{
        "check": f.check, "tool": f.tool, "param": f.param,
        "severity": f.severity.value, "confidence": f.confidence.value,
        "cwe": f.cwe, "title": f.title, "payload": f.payload,
        "evidence": f.evidence, "remediation": f.remediation,
    } for f in findings]
    return json.dumps(doc, indent=2)

def to_sarif(result) -> str:
    scan, findings = _split(result)
    rules = {f.check for f in findings}
    run = {
        "tool": {"driver": {"name": "mcpsnare",
                            "rules": [{"id": r} for r in sorted(rules)]}},
        "results": [{
            "ruleId": f.check,
            "level": "error" if f.severity.value in ("critical", "high") else "warning",
            "message": {"text": f"{f.title} | payload={f.payload} | {f.evidence}"},
        } for f in findings],
    }
    if scan is not None:
        meta = _scan_meta(scan)
        run["invocations"] = [{"executionSuccessful": True, "properties": meta}]
        run["properties"] = meta
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }, indent=2)

def to_markdown(result) -> str:
    scan, findings = _split(result)
    lines = ["# mcpsnare report", ""]
    if scan is not None:
        lines += ["## Scan metadata", "",
                  f"- **Target:** `{scan.target or '(n/a)'}` ({scan.transport})",
                  f"- **Tools:** {scan.tools_discovered} discovered, {scan.tools_reachable} reachable",
                  f"- **Checks:** {', '.join(scan.checks_executed)}",
                  f"- **Aggressive:** {scan.aggressive}",
                  f"- **Time-based points skipped:** {scan.time_based_skipped}", ""]
        notes = _scan_notes(scan)
        for note in notes:
            lines.append(f"> {note}")
        if notes:
            lines.append("")
    lines += [f"**Findings:** {len(findings)}", ""]
    for f in findings:
        lines += [f"## {f.title}",
                  f"- **Severity:** {f.severity.value.upper()}  ({f.confidence.value})",
                  f"- **CWE:** {f.cwe}",
                  f"- **Tool/param:** `{f.tool}` / `{f.param}`",
                  f"- **Payload:** `{f.payload}`",
                  f"- **Evidence:** {f.evidence}",
                  f"- **Remediation:** {f.remediation}", ""]
    return "\n".join(lines)
