import re
from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_PAYLOADS = ["../../../../../../etc/passwd",
             "..\\..\\..\\..\\..\\..\\windows\\win.ini"]
_CANARY = re.compile(r"root:x:0:0:|\[fonts\]", re.IGNORECASE)


@register
class PathTraversal:
    id = "path_traversal"
    def generate(self, point, ctx):
        out = []
        for pl in _PAYLOADS:
            out.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl)))
        return out
    def evaluate(self, probe, response, ctx):
        if _CANARY.search(response or ""):
            return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                           severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-22",
                           title=f"Path traversal in {probe.point.tool}.{probe.point.param_name}",
                           payload=probe.payload, evidence=(response or "")[:200],
                           remediation="Resolve and contain paths within an allowed base dir.")
        return None
