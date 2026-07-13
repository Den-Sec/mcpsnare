"""Active code / eval-sink injection (CWE-94).

The passive `capability` lens FLAGS a tool that declares code execution
(`execute_revit_code`); this check tries to CONFIRM it. `cmd_injection` sends shell
metacharacters (`; curl`, `$(curl)`), which are a SyntaxError inside a language
interpreter (Python / IronPython / JS `eval`/`exec`) - so they never call back and a
code sink is missed even against a live backend. This check speaks the sink's language:
it injects language-native payloads that either (a) call back out-of-band, or (b)
evaluate a distinctive arithmetic canary whose result is reflected in the response.

Selection heuristic: only string params whose name looks like a code sink
(`code|script|expression|eval|python|ironpython|snippet|formula`, incl. plurals; NOT
`query`/`command` - those are SQL / shell, covered by sql_injection / cmd_injection).
Gating is a precision optimisation, not a safety gate: a payload sent at a non-code sink
simply produces no callback and no marker, hence no finding.

Confidence: CONFIRMED (OOB callback proves execution), FIRM (arithmetic canary reflected
and absent from the benign baseline), TENTATIVE (canary reflected but no baseline to
corroborate).
"""
import re

from mcpsnare.inject.jsonpath import parse_path
from mcpsnare.models import Probe, Finding, Severity, Confidence
from mcpsnare.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

# Param-name tokens that mark a likely code/eval sink (exact token match, camelCase- and
# snake_case-aware; plurals included). `query`/`command` are deliberately absent.
_CODE_PARAM_TOKENS = {
    "code", "codes", "script", "scripts", "expression", "expressions", "expr",
    "eval", "python", "ironpython", "snippet", "snippets", "formula", "formulas",
}

# Arithmetic canary: a unique prefix joined to str(7*7). The joined marker
# "mcpsnareCANARY49" only appears if the sink EVALUATED the expression - an echo of the
# source keeps the literal " + str(7*7)" text, so the marker proves evaluation, not reflection.
_CANARY_EXPR = "7*7"
_CANARY_MARKER = "mcpsnareCANARY49"
_MARKER_RE = re.compile(re.escape(_CANARY_MARKER))

# OOB payloads, language-native, one per interpreter family. {url} is a per-payload OOB
# token URL (so the firing language is named). timeout guards against a hang if the target
# reaches the listener but the listener stalls.
_OOB_TEMPLATES = (
    "__import__('urllib.request').request.urlopen('{url}', timeout=5)",   # CPython 3 stdlib
    "__import__('urllib2').urlopen('{url}', timeout=5)",                   # Python 2 / IronPython (Revit)
    "require('http').get('{url}')",                                       # Node.js eval sink
)

# Arithmetic-canary payloads (non-blocking, always sent). Expression form returns the
# marker from an eval sink; print form emits it from an exec sink; String() covers JS eval.
_CANARY_TEMPLATES = (
    "'mcpsnareCANARY'+str({expr})",         # Python eval -> 'mcpsnareCANARY49'
    "print('mcpsnareCANARY'+str({expr}))",  # Python exec -> prints it
    "'mcpsnareCANARY'+String({expr})",      # JS eval -> 'mcpsnareCANARY49'
)

# Blocking time-based payload (~_SLEEP_SECONDS delay), sent only with --aggressive.
_SLEEP_TEMPLATES = (
    "__import__('time').sleep({n})",        # Python / IronPython
)


def _leaf_name(json_path):
    for seg in reversed(parse_path(json_path)):
        if isinstance(seg, str):
            return seg
    return json_path


def _is_code_param(json_path):
    name = _leaf_name(json_path)
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    tokens = {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}
    return bool(tokens & _CODE_PARAM_TOKENS)


@register
class CodeInjection:
    id = "code_injection"
    time_based = True   # consulted by the engine's time_based_skipped accounting

    def generate(self, point, ctx):
        if not _is_code_param(point.json_path):
            return []
        probes = []
        if ctx.oob is not None:
            for tpl in _OOB_TEMPLATES:
                token, url = ctx.oob.new_token()
                payload = tpl.format(url=url)
                probes.append(Probe(check=self.id, point=point, payload=payload,
                                    args=point.set(payload), token=token))
        for tpl in _CANARY_TEMPLATES:
            payload = tpl.format(expr=_CANARY_EXPR)
            probes.append(Probe(check=self.id, point=point, payload=payload,
                                args=point.set(payload), meta={"canary": True}))
        if getattr(ctx, "aggressive", False):
            for tpl in _SLEEP_TEMPLATES:
                payload = tpl.format(n=_SLEEP_SECONDS)
                probes.append(Probe(check=self.id, point=point, payload=payload,
                                    args=point.set(payload),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes

    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED,
                                 f"OOB callback received for code payload {probe.payload!r}")
        if probe.meta.get("time_based"):
            elapsed = probe.meta.get("elapsed", 0)
            sleep_s = probe.meta["threshold"]
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                margin = max(baseline.latency + sleep_s * 0.8, baseline.latency * _LATENCY_MULT)
                evidence = f"response delayed {elapsed:.1f}s vs baseline {baseline.latency:.1f}s (code sleep)"
            else:
                margin = sleep_s  # no calibration: fall back to the fixed threshold
                evidence = f"response delayed {elapsed:.1f}s (code sleep)"
            if elapsed >= margin:
                return self._finding(probe, Confidence.FIRM, evidence)
            return None
        if probe.meta.get("canary"):
            if not _MARKER_RE.search(response or ""):
                return None
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                if _MARKER_RE.search(baseline.response or ""):
                    return None  # marker already in benign baseline = not triggered by our input
                return self._finding(probe, Confidence.FIRM,
                                     f"arithmetic canary {_CANARY_EXPR}->49 evaluated in output "
                                     f"(marker {_CANARY_MARKER!r} absent in baseline)")
            return self._finding(probe, Confidence.TENTATIVE,
                                 f"arithmetic canary {_CANARY_EXPR}->49 evaluated in output "
                                 f"(marker {_CANARY_MARKER!r}, no baseline to corroborate)")
        return None

    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.CRITICAL, confidence=conf, cwe="CWE-94",
                       title=f"Code injection in {probe.point.tool}.{probe.point.param_name}",
                       payload=probe.payload, evidence=evidence,
                       remediation=("Never eval/exec tool input. If code execution is a real feature, "
                                    "sandbox it (no host process / network / filesystem), and gate it behind "
                                    "explicit opt-in plus per-call human approval."))
