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
class InjectionPoint:
    tool: str
    json_path: str
    base_args: dict
    param_name: str


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
