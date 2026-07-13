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
        from mcpsnare.inject.jsonpath import deep_set
        args = copy.deepcopy(self.base_args)
        deep_set(args, self.json_path, value)
        return args

    def embed(self, payload, position="suffix") -> dict:
        """Return base_args with ``payload`` embedded onto the baseline-VALID value at
        json_path (suffix by default), rather than replacing it. Reaches vulns behind
        format/content validation. Falls back to the payload alone if the leaf is absent."""
        import copy
        from mcpsnare.inject.jsonpath import deep_get, deep_set
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


def _dedup_preserve(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


@dataclass(eq=False)
class ScanResult:
    """A scan's findings plus the metadata a report needs to be honest: what was
    targeted, how many tools were seen/reachable, which checks ran, and whether the
    blocking time-based probes were skipped. A bare ``list[Finding]`` cannot tell an
    empty ``findings: []`` (secure) from "nothing was actually tested" - this can.

    It is deliberately list-like (``__iter__``/``__len__``/``__getitem__`` and list
    equality) so the many callers/tests that iterate or ``len()`` a scan result keep
    working unchanged, and ``__add__`` merges the two passes the CLI runs (tools +
    resource templates): findings concatenate, counters sum, ``aggressive`` ORs.
    """
    findings: list = field(default_factory=list)
    target: str = ""
    transport: str = ""
    tools_discovered: int = 0
    tools_reachable: int = 0
    checks_executed: list = field(default_factory=list)
    aggressive: bool = False
    time_based_skipped: int = 0

    def __iter__(self):
        return iter(self.findings)

    def __len__(self):
        return len(self.findings)

    def __getitem__(self, index):
        return self.findings[index]

    def __eq__(self, other):
        if isinstance(other, ScanResult):
            return (self.findings == other.findings
                    and self.target == other.target
                    and self.transport == other.transport
                    and self.tools_discovered == other.tools_discovered
                    and self.tools_reachable == other.tools_reachable
                    and self.checks_executed == other.checks_executed
                    and self.aggressive == other.aggressive
                    and self.time_based_skipped == other.time_based_skipped)
        if isinstance(other, list):
            return list(self.findings) == other  # back-compat: `findings == []`
        return NotImplemented

    def __add__(self, other):
        if isinstance(other, ScanResult):
            return ScanResult(
                findings=list(self.findings) + list(other.findings),
                target=self.target or other.target,
                transport=self.transport or other.transport,
                tools_discovered=self.tools_discovered + other.tools_discovered,
                tools_reachable=self.tools_reachable + other.tools_reachable,
                checks_executed=_dedup_preserve(list(self.checks_executed) + list(other.checks_executed)),
                aggressive=self.aggressive or other.aggressive,
                time_based_skipped=self.time_based_skipped + other.time_based_skipped,
            )
        return NotImplemented
