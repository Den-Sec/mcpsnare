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
        if not hits:
            return None
        baseline = getattr(ctx, "baseline", None)
        if baseline is not None:
            base_hits = {m.pattern for m in _MARKERS if m.search(baseline.response or "")}
            triggered = [h for h in hits if h not in base_hits]
            if not triggered:
                return None  # secrets also present in benign baseline = normal output, not a leak
            return self._finding(probe, Confidence.FIRM,
                                 f"secret-shaped match triggered by input (absent in baseline): {triggered}")
        if len(hits) >= 2:
            return self._finding(probe, Confidence.TENTATIVE,
                                 f"secret-shaped pattern match (no baseline to diff): {hits}")
        return None

    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.HIGH, confidence=conf, cwe="CWE-200",
                       title=f"Secret/info leak via {probe.point.tool}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Never return secrets/credentials in tool output or errors.")
