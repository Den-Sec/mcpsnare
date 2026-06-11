from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict


@dataclass
class ToolBaseline:
    latency: float
    response: str


@dataclass
class InjectionPoint:
    tool: str
    json_path: str
    base_args: dict
    param_name: str

    def set(self, value) -> dict:
        """Return a deep copy of base_args with ``value`` deep-set at json_path.

        Deep-copies so the shared baseline is never mutated across probes.
        """
        import copy
        from mcprobe.inject.jsonpath import deep_set
        args = copy.deepcopy(self.base_args)
        deep_set(args, self.json_path, value)
        return args

    def embed(self, payload, position="suffix") -> dict:
        """Return base_args with ``payload`` embedded onto the baseline-VALID value at
        json_path (suffix by default), rather than replacing it. Reaches vulns behind
        format/content validation. Falls back to the payload alone if the leaf is absent."""
        import copy
        from mcprobe.inject.jsonpath import deep_get, deep_set
        args = copy.deepcopy(self.base_args)
        try:
            valid = deep_get(args, self.json_path)
        except (KeyError, IndexError, TypeError):
            valid = ""
        valid = valid if isinstance(valid, str) else ""
        combined = f"{valid}{payload}" if position == "suffix" else f"{payload}{valid}"
        deep_set(args, self.json_path, combined)
        return args


@dataclass
class Probe:
    check: str
    point: InjectionPoint
    payload: str
    args: dict
    token: str | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class Finding:
    check: str
    tool: str
    param: str
    severity: Severity
    confidence: Confidence
    cwe: str
    title: str
    payload: str
    evidence: str
    remediation: str
