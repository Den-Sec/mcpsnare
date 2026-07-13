"""Passive capability / tool-surface lens.

Vetting an MCP server for adoption is not only "can I actively confirm an
injection" - it is "what dangerous capability does this server DECLARE". A tool
literally named `execute_revit_code` with description "Execute IronPython code
directly in Revit context" is an arbitrary-code-execution primitive whether or
not a live backend is reachable to confirm it. The active checks miss this: they
probe injection points and need an OOB/canary callback, so against a thin proxy
(or with no live backend) they stay silent and the report reads as "secure".

This check reads the tool manifest only (name, description, parameter names) with
ZERO tool calls and flags declared dangerous capabilities. Findings are honest
about what they are: a capability the tool self-describes, NOT an exploit
confirmation - hence FIRM at most (multiple independent signals) or TENTATIVE
(a single/ambiguous signal), never CONFIRMED. The taxonomy is name-verb gated and
tuned to avoid the obvious false positives (SQL `execute_query`, OAuth `code`
param, a `security` param, `drop_pin`, a `load` that only reads).
"""
import re

from mcpsnare.models import Finding, Severity, Confidence
from mcpsnare.checks.base import register_passive

_MAX_DEPTH = 4

# Parameter-name shapes (lowercased leaf property names).
_PATH_PARAMS = {"path", "file_path", "filepath", "filename", "file", "dir",
                "directory", "output_path", "outputpath", "dest", "destination",
                "src", "source", "output", "save_path", "savepath"}
_URL_PARAMS = {"url", "uri", "endpoint", "webhook", "callback", "href", "link_url"}

# Regex phrases scanned against the (lowercased) tool description. Note "statement"
# is deliberately absent from _RE_EXEC so "execute a SQL statement" is not read as
# arbitrary code execution.
_RE_EXEC = re.compile(
    r"(execute|run|eval|evaluate|interpret)\b[^.]{0,40}\b"
    r"(code|script|python|ironpython|expression|command)"
    r"|arbitrary\s+(code|script|command|python)"
    r"|ironpython")
_RE_DESTRUCTIVE = re.compile(
    r"\b(delete|deletes|remove|removes|destroy|destroys|truncate|"
    r"purge|erase|wipe|permanently)\b")
_RE_FS = re.compile(
    r"\b(save|write|writes|export|exports|dump|upload)\b[^.]{0,40}\b"
    r"(file|path|disk|document|folder|directory)"
    r"|\bfile\s*path\b|\bfilesystem\b")


def _tokens(s):
    return set(t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t)


def _collect_param_names(schema, depth=0, out=None):
    """Recursively collect lowercased property names from a JSON schema.

    Bounded depth + robust to malformed schemas (never raises)."""
    if out is None:
        out = set()
    try:
        if not isinstance(schema, dict) or depth > _MAX_DEPTH:
            return out
        props = schema.get("properties")
        if isinstance(props, dict):
            for name, sub in props.items():
                out.add(str(name).lower())
                _collect_param_names(sub, depth + 1, out)
        items = schema.get("items")
        if isinstance(items, dict):
            _collect_param_names(items, depth + 1, out)
        for key in ("anyOf", "oneOf", "allOf"):
            for sub in schema.get(key, []) or []:
                _collect_param_names(sub, depth + 1, out)
    except Exception:
        pass
    return out


@register_passive
class Capability:
    id = "capability"

    def inspect(self, tool, ctx):
        desc_l = (tool.description or "").lower()
        ntok = _tokens(tool.name or "")
        params = _collect_param_names(tool.input_schema or {})
        has_path_param = bool(params & _PATH_PARAMS) or any(
            p.endswith(("_path", "_file", "path")) for p in params)
        # Exact / suffix match only - substring "in" would flag a `security` param
        # (contains "uri") or `curl_opts` as SSRF.
        has_url_param = bool(params & _URL_PARAMS) or any(
            p.endswith(("_url", "_uri")) for p in params)

        findings = []
        write_verbs = ntok & {"save", "write", "export", "dump", "upload"}
        load_verbs = ntok & {"load", "import", "link"}

        # --- code / command execution (CRITICAL, CWE-94) --- requires >=2 independent
        # signals, so a lone ambiguous "execute" (execute_query) or a lone `code` param
        # (OAuth authorization code) does not fire a CRITICAL.
        code_signals = []
        exec_verbs = ntok & {"execute", "exec", "eval", "run", "ironpython"}
        if exec_verbs:
            code_signals.append(f"name verb ({'/'.join(sorted(exec_verbs))})")
        if ntok & {"code", "script", "python", "ironpython"}:
            code_signals.append("code noun in name")
        if _RE_EXEC.search(desc_l):
            code_signals.append("description declares code/script execution")
        code_params = params & {"code", "script", "expression", "eval", "command", "cmd", "python", "ironpython"}
        if code_params:
            code_signals.append(f"parameter ({'/'.join(sorted(code_params))})")
        if len(code_signals) >= 2:
            findings.append(self._f(
                tool, "code-exec", Severity.CRITICAL, "CWE-94", Confidence.FIRM, code_signals,
                "arbitrary code/command execution",
                "Do not expose an arbitrary-code-execution tool by default; gate behind explicit opt-in AND per-call human confirmation, and treat it as an unbounded RCE primitive."))

        # --- filesystem write (HIGH, CWE-73) --- writes to disk at a caller path.
        if write_verbs and (has_path_param or _RE_FS.search(desc_l)):
            sigs = [f"name verb ({'/'.join(sorted(write_verbs))})"]
            if has_path_param:
                sigs.append("filesystem-path parameter")
            if _RE_FS.search(desc_l):
                sigs.append("description declares a file/path write")
            findings.append(self._f(
                tool, "fs-write", Severity.HIGH, "CWE-73",
                Confidence.FIRM if len(sigs) >= 2 else Confidence.TENTATIVE, sigs,
                "writes files at a caller-controlled path",
                "Confine file paths to an allowlisted base directory, canonicalize and reject traversal/UNC, and never default to overwrite."))

        # --- filesystem load/link of an untrusted external file (HIGH, CWE-434) ---
        # load/import/link READ an external file into the app (parser attack surface),
        # which is a file-load, not a write - hence CWE-434, not CWE-73.
        if load_verbs:
            sigs = [f"name verb ({'/'.join(sorted(load_verbs))})"]
            if has_path_param:
                sigs.append("filesystem-path parameter")
            findings.append(self._f(
                tool, "fs-load", Severity.HIGH, "CWE-434",
                Confidence.FIRM if len(sigs) >= 2 else Confidence.TENTATIVE, sigs,
                "loads/links an untrusted external file (parser attack surface) from a caller-controlled path",
                "Validate and allowlist loaded file types/paths; treat externally-supplied files as untrusted parser input."))

        # --- destructive / state-change (HIGH, CWE-749) --- name-verb gated. "drop" is
        # excluded (ambiguous: DB drop vs map/UI pin drop). Strong verbs are FIRM;
        # ambiguous verbs (remove/overwrite) stay TENTATIVE.
        strong_destr = ntok & {"delete", "destroy", "truncate", "purge", "erase", "wipe"}
        ambig_destr = ntok & {"remove", "overwrite"}
        if strong_destr or ambig_destr:
            sigs = [f"name verb ({'/'.join(sorted(strong_destr | ambig_destr))})"]
            if _RE_DESTRUCTIVE.search(desc_l):
                sigs.append("description declares a destructive operation")
            findings.append(self._f(
                tool, "destructive", Severity.HIGH, "CWE-749",
                Confidence.FIRM if strong_destr else Confidence.TENTATIVE, sigs,
                "irreversible/destructive state change",
                "Require confirmation or a dry-run for destructive tools, and expose a destructiveHint annotation so clients do not auto-approve them."))

        # --- filesystem read (MEDIUM, CWE-22) --- only if not already a write/load.
        if not (write_verbs or load_verbs):
            read_verbs = ntok & {"read", "download", "cat", "open"}
            if read_verbs and has_path_param:
                findings.append(self._f(
                    tool, "fs-read", Severity.MEDIUM, "CWE-22", Confidence.FIRM,
                    [f"name verb ({'/'.join(sorted(read_verbs))})", "filesystem-path parameter"],
                    "reads files at a caller-controlled path",
                    "Confine read paths to an allowlisted base directory and reject traversal/UNC."))

        # --- network / SSRF-capable fetch (MEDIUM, CWE-918) ---
        if has_url_param:
            net_verbs = ntok & {"fetch", "http", "request", "webhook", "download", "curl"}
            sigs = ["url/uri parameter"]
            if net_verbs:
                sigs.append(f"name verb ({'/'.join(sorted(net_verbs))})")
            findings.append(self._f(
                tool, "network", Severity.MEDIUM, "CWE-918",
                Confidence.FIRM if len(sigs) >= 2 else Confidence.TENTATIVE, sigs,
                "issues network requests to a caller-controlled URL",
                "Validate/allowlist outbound hosts and block internal/link-local targets to prevent SSRF."))

        return findings

    def _f(self, tool, category, severity, cwe, confidence, signals, what, remediation):
        evidence = (f"Passive manifest analysis (no exploit confirmation): tool "
                    f"'{tool.name}' declares {what}. Signals: {'; '.join(signals)}.")
        return Finding(
            check=self.id, tool=tool.name, param=category,
            severity=severity, confidence=confidence, cwe=cwe,
            title=f"Dangerous capability declared: {category} ({tool.name})",
            payload="(passive: tool manifest)", evidence=evidence,
            remediation=remediation)
