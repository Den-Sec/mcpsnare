from dataclasses import dataclass
from typing import Callable, Protocol
from mcprobe.models import InjectionPoint, Probe, Finding


@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None


class Check(Protocol):
    id: str
    def generate(self, point: InjectionPoint, ctx: "CheckContext") -> list[Probe]: ...
    def evaluate(self, probe: Probe, response: str, ctx: "CheckContext") -> Finding | None: ...


REGISTRY: dict[str, "Check"] = {}


def register(cls):
    REGISTRY[cls.id] = cls()
    return cls
