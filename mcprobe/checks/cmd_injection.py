from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

@register
class CmdInjection:
    id = "cmd_injection"
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            for tpl in ("; curl {url}", "$(curl {url})", "& curl {url}"):
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED,
                                 f"OOB callback received for payload {probe.payload!r}")
        if probe.meta.get("time_based"):
            elapsed = probe.meta.get("elapsed", 0)
            sleep_s = probe.meta["threshold"]
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                margin = max(baseline.latency + sleep_s * 0.8, baseline.latency * _LATENCY_MULT)
                evidence = f"response delayed {elapsed:.1f}s vs baseline {baseline.latency:.1f}s"
            else:
                margin = sleep_s  # no calibration: fall back to the fixed threshold
                evidence = f"response delayed {elapsed:.1f}s"
            if elapsed >= margin:
                return self._finding(probe, Confidence.FIRM, evidence)
        return None
    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.CRITICAL, confidence=conf, cwe="CWE-78",
                       title=f"Command injection in {probe.point.tool}.{probe.point.param_name}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Never pass tool input to a shell; use exec with arg arrays / allowlists.")
