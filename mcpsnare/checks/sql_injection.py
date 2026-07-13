import re
from mcpsnare.models import Probe, Finding, Severity, Confidence
from mcpsnare.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

# Distinctive SQL error signatures across common engines.
_ERROR_SIGNS = re.compile(
    r"SQL syntax|SQLSTATE|ORA-\d{5}|mysql_fetch|mysql_num_rows|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"you have an error in your SQL|near \"[^\"]*\": syntax error|"
    r"PG::\w+Error|pg_query|psql:.*(?:ERROR|FATAL)|SQLite3?::|Microsoft OLE DB|"
    r"ODBC SQL Server|Npgsql\.|System\.Data\.SqlClient",
    re.IGNORECASE,
)

# Non-blocking error-based payloads (always sent).
_ERROR_PAYLOADS = ("'", '"', "')", "' OR '1'='1")

# Blocking time-based payloads (~_SLEEP_SECONDS), aggressive-only. MySQL, MSSQL, PostgreSQL.
_TIME_TEMPLATES = (
    "' OR SLEEP({n})-- ",
    "'; WAITFOR DELAY '0:0:{n}'-- ",
    "' OR pg_sleep({n})-- ",
)


@register
class SqlInjection:
    id = "sql_injection"
    time_based = True   # emits blocking sleep probes under --aggressive (engine skip accounting)

    def generate(self, point, ctx):
        probes = []
        for pl in _ERROR_PAYLOADS:
            probes.append(Probe(check=self.id, point=point, payload=pl,
                                args=point.set(pl), meta={"error_based": True}))
        if getattr(ctx, "aggressive", False):
            for tpl in _TIME_TEMPLATES:
                pl = tpl.format(n=_SLEEP_SECONDS)
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes

    def evaluate(self, probe, response, ctx):
        if probe.meta.get("time_based"):
            elapsed = probe.meta.get("elapsed", 0)
            sleep_s = probe.meta["threshold"]
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                margin = max(baseline.latency + sleep_s * 0.8, baseline.latency * _LATENCY_MULT)
                evidence = f"response delayed {elapsed:.1f}s vs baseline {baseline.latency:.1f}s (SQL sleep)"
            else:
                margin = sleep_s
                evidence = f"response delayed {elapsed:.1f}s (SQL sleep)"
            if elapsed >= margin:
                return self._finding(probe, Confidence.FIRM, evidence)
            return None
        if not _ERROR_SIGNS.search(response or ""):
            return None
        baseline = getattr(ctx, "baseline", None)
        if baseline is not None:
            if _ERROR_SIGNS.search(baseline.response or ""):
                return None  # error already in benign baseline = not triggered
            return self._finding(probe, Confidence.FIRM,
                                 "SQL error signature triggered by quote payload (absent in baseline)")
        return self._finding(probe, Confidence.TENTATIVE,
                             "SQL error signature matched (no baseline to corroborate)")

    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.HIGH, confidence=conf, cwe="CWE-89",
                       title=f"SQL injection in {probe.point.tool}.{probe.point.param_name}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Use parameterised queries / prepared statements; never concatenate input into SQL.")
