"""Passive tool-poisoning / prompt-injection lens.

An MCP client feeds tool and parameter DESCRIPTIONS verbatim to the driving LLM,
which makes those descriptions a supply-chain / tool-poisoning vector: a malicious
(or compromised-upstream) server can hide "ignore previous instructions / exfiltrate
X to http://..." directives, or invisible unicode, inside a tool's description. A
vetter should see this before adoption. This check reads the manifest only (tool +
parameter descriptions) with ZERO tool calls.

Signals are high-precision (hidden unicode and imperative-injection phrasing almost
never appear in a legitimate description); bare URLs are reported at LOW as a lead
to eyeball, not a confirmed attack. Findings are TENTATIVE - this is a heuristic
read of text, not an exploit confirmation.
"""
import re

from mcpsnare.models import Finding, Severity, Confidence
from mcpsnare.checks.base import register_passive

_MAX_DEPTH = 4

_IMPERATIVES = [re.compile(p, re.I) for p in [
    r"ignore\s+(all\s+|the\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|context|message)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above|earlier|instruction)",
    r"(system|developer)\s+prompt",
    r"\bnew\s+instructions?\s*:",
    r"do\s+not\s+(tell|mention|inform|reveal|disclose)",
    r"you\s+must\s+(always|now|instead)",
    r"override\s+(the\s+)?(system|previous|safety|instruction)",
    r"exfiltrat",
    r"send\b[^.]{0,40}\b(http|attacker|the\s+following|to\s+the\s+url)",
]]

# Invisible / directional-control unicode that has no business in a description.
# Built from integer codepoint ranges via chr() so the SOURCE stays pure ASCII
# (no literal invisible characters that an editor/encoding could silently corrupt).
# U+200D (ZWJ) is deliberately excluded - it appears legitimately in emoji sequences.
_HIDDEN_RANGES = [
    (0x200B, 0x200C),   # zero-width space, zero-width non-joiner
    (0x200E, 0x200F),   # LRM, RLM
    (0x2060, 0x2060),   # word joiner
    (0xFEFF, 0xFEFF),   # zero-width no-break space / BOM
    (0x202A, 0x202E),   # bidi embeddings / overrides
    (0x2066, 0x2069),   # bidi isolates
    (0xE0000, 0xE007F),  # unicode tag characters
]
_HIDDEN_UNICODE = re.compile(
    "[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _HIDDEN_RANGES) + "]")

_URL = re.compile(r"https?://[^\s)\]}\"'>]+", re.I)


def _collect_texts(schema, depth=0, out=None):
    """Collect all description strings inside a JSON schema (robust, depth-capped)."""
    if out is None:
        out = []
    try:
        if not isinstance(schema, dict) or depth > _MAX_DEPTH:
            return out
        d = schema.get("description")
        if isinstance(d, str) and d:
            out.append(d)
        props = schema.get("properties")
        if isinstance(props, dict):
            for sub in props.values():
                _collect_texts(sub, depth + 1, out)
        items = schema.get("items")
        if isinstance(items, dict):
            _collect_texts(items, depth + 1, out)
        for key in ("anyOf", "oneOf", "allOf"):
            for sub in schema.get(key, []) or []:
                _collect_texts(sub, depth + 1, out)
    except Exception:
        pass
    return out


@register_passive
class ToolPoisoning:
    id = "tool_poisoning"

    def inspect(self, tool, ctx):
        texts = []
        if tool.description:
            texts.append(tool.description)
        texts += _collect_texts(tool.input_schema or {})
        blob = "\n".join(texts)
        if not blob:
            return []

        findings = []

        imperative_hits = sorted({p.pattern for p in _IMPERATIVES if p.search(blob)})
        if imperative_hits:
            findings.append(self._f(
                tool, "imperative", Severity.MEDIUM, "CWE-94",
                f"description/parameter text contains imperative-injection phrasing "
                f"(the LLM reads this verbatim): {len(imperative_hits)} pattern(s) matched",
                "Review the tool/parameter descriptions; a server can steer the agent through them. Do not adopt a server whose descriptions embed instructions to the model."))

        hidden = _HIDDEN_UNICODE.findall(blob)
        if hidden:
            codepoints = sorted({f"U+{ord(c):04X}" for c in hidden})
            findings.append(self._f(
                tool, "hidden-unicode", Severity.MEDIUM, "CWE-94",
                f"description contains invisible/bidirectional unicode ({', '.join(codepoints)}) "
                f"- a classic place to hide instructions from a human reviewer",
                "Reject or sanitize non-printable unicode in tool/parameter descriptions before trusting the server."))

        urls = _URL.findall(blob)
        if urls and not imperative_hits:
            findings.append(self._f(
                tool, "url", Severity.LOW, "CWE-94",
                f"description embeds URL(s) fed to the model: {urls[0]}"
                + (f" (+{len(urls) - 1} more)" if len(urls) > 1 else ""),
                "Eyeball embedded URLs in tool descriptions; they can direct the agent to attacker content."))

        return findings

    def _f(self, tool, kind, severity, cwe, evidence, remediation):
        return Finding(
            check=self.id, tool=tool.name, param=kind,
            severity=severity, confidence=Confidence.TENTATIVE, cwe=cwe,
            title=f"Possible tool-poisoning ({kind}) in {tool.name} description",
            payload="(passive: tool manifest)",
            evidence="Passive manifest analysis (no exploit confirmation): " + evidence + ".",
            remediation=remediation)
