import re
from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_MARKERS = [re.compile(p) for p in [
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}",
    r"(?i)api[_-]?key\s*[=:]\s*\S+", r"(?i)secret\s*[=:]\s*\S+",
    r"xox[baprs]-[0-9A-Za-z-]+", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."]]


@register
class InfoLeak:
    id = "info_leak"
    def generate(self, point, ctx):
        return [Probe(check=self.id, point=point, payload="mcprobe-probe",
                      args=point.set("mcprobe-probe"))]
    def evaluate(self, probe, response, ctx):
        hits = [m.pattern for m in _MARKERS if m.search(response or "")]
        if len(hits) >= 2:
            return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                           severity=Severity.HIGH, confidence=Confidence.FIRM, cwe="CWE-200",
                           title=f"Secret/info leak via {probe.point.tool}",
                           payload=probe.payload, evidence=f"matched: {hits}",
                           remediation="Never return secrets/credentials in tool output or errors.")
        return None
