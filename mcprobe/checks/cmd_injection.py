from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_SLEEP_SECONDS = 5

@register
class CmdInjection:
    id = "cmd_injection"
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            token, url = ctx.oob.new_token()
            for tpl in (f"; curl {url}", f"$(curl {url})", f"& curl {url}"):
                pl = f"mcprobe{tpl}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED, "OOB callback received")
        if probe.meta.get("time_based") and probe.meta.get("elapsed", 0) >= probe.meta["threshold"]:
            return self._finding(probe, Confidence.FIRM,
                                 f"response delayed {probe.meta['elapsed']:.1f}s")
        return None
    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.CRITICAL, confidence=conf, cwe="CWE-78",
                       title=f"Command injection in {probe.point.tool}.{probe.point.param_name}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Never pass tool input to a shell; use exec with arg arrays / allowlists.")
