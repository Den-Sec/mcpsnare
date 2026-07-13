from dataclasses import dataclass
from typing import Callable, Protocol
from mcpsnare.models import InjectionPoint, Probe, Finding, ToolBaseline, ToolInfo


@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None
    baseline: ToolBaseline | None = None
    aggressive: bool = False


class Check(Protocol):
    id: str
    def generate(self, point: InjectionPoint, ctx: "CheckContext") -> list[Probe]: ...
    def evaluate(self, probe: Probe, response: str, ctx: "CheckContext") -> Finding | None: ...


REGISTRY: dict[str, "Check"] = {}


def register(cls):
    REGISTRY[cls.id] = cls()
    return cls


class PassiveCheck(Protocol):
    """A manifest-level check: inspects a tool's declared surface (name,
    description, input schema) with ZERO tool calls. Unlike Check, it does not
    probe an injection point or need a response - it runs once per tool straight
    from list_tools(). Used for vetting/adoption scans where the dangerous
    capability a target declares matters even when active probing cannot (or must
    not) reach a live backend."""
    id: str
    def inspect(self, tool: ToolInfo, ctx: "CheckContext") -> list[Finding]: ...


PASSIVE_REGISTRY: dict[str, "PassiveCheck"] = {}


def register_passive(cls):
    PASSIVE_REGISTRY[cls.id] = cls()
    return cls
