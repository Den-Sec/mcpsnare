from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

@register
class SSRF:
    id = "ssrf"
    def generate(self, point, ctx):
        if ctx.oob is None:
            return []
        token, url = ctx.oob.new_token()
        return [Probe(check=self.id, point=point, payload=url, args=point.set(url), token=token)]
    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                           severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-918",
                           title=f"SSRF in {probe.point.tool}.{probe.point.param_name}",
                           payload=probe.payload, evidence="OOB callback received",
                           remediation="Validate/allowlist outbound URLs; block internal ranges & metadata IPs.")
        return None
