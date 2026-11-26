"""--target-os: send only the shell payloads that can run on the target's OS family."""
import sys

import pytest

from mcpsnare.checks.base import CheckContext
from mcpsnare.checks.cmd_injection import CmdInjection, templates_for
from mcpsnare.cli import build_parser
from mcpsnare.engine import resolve_target_os
from mcpsnare.models import InjectionPoint, ScanResult
from mcpsnare.report.render import to_json


class _FakeOOB:
    def __init__(self):
        self.n = 0

    def new_token(self):
        self.n += 1
        return f"t{self.n}", f"http://oob.test/t{self.n}"

    def interactions(self, token):
        return []


def _point():
    return InjectionPoint(tool="run", json_path="cmd", base_args={"cmd": "x"}, param_name="cmd")


def _payloads(target_os, aggressive=False):
    ctx = CheckContext(oob=_FakeOOB(), transport="stdio", aggressive=aggressive, target_os=target_os)
    return [p.payload for p in CmdInjection().generate(_point(), ctx)]


def test_all_is_default_and_sends_every_family():
    ctx = CheckContext(oob=None, transport="stdio")
    assert ctx.target_os == "all"
    joined = " ".join(_payloads("all"))
    for marker in ("; curl ", "$(curl ", "& curl ", "| curl ", "; iwr ", "; curl.exe "):
        assert marker in joined


def test_posix_drops_powershell_only_payloads():
    joined = " ".join(_payloads("posix"))
    assert "; iwr " not in joined and "curl.exe" not in joined
    assert "$(curl " in joined and "; curl " in joined


def test_windows_drops_posix_only_payloads():
    joined = " ".join(_payloads("windows"))
    assert "$(curl " not in joined
    assert "; curl http" not in joined          # POSIX "; curl" (curl.exe still allowed)
    assert "& curl " in joined and "; iwr " in joined and "curl.exe" in joined


def test_filter_reduces_probe_count():
    assert len(_payloads("posix")) < len(_payloads("all"))
    assert len(_payloads("windows")) < len(_payloads("all"))


@pytest.mark.parametrize("target_os,absent,present", [
    ("posix", "Start-Sleep", "; sleep"),
    ("windows", "; sleep", "Start-Sleep"),
])
def test_sleep_payloads_follow_target_os(target_os, absent, present):
    joined = " ".join(_payloads(target_os, aggressive=True))
    assert absent not in joined and present in joined


def test_every_template_belongs_to_some_family():
    assert set(templates_for("posix")) | set(templates_for("windows")) == set(templates_for("all"))


def test_auto_resolves_to_local_platform_for_stdio_and_all_for_http():
    local = "windows" if sys.platform == "win32" else "posix"
    assert resolve_target_os("auto", "stdio") == local
    assert resolve_target_os("auto", "http") == "all"
    assert resolve_target_os("posix", "http") == "posix"


def test_cli_flag_defaults_to_all_and_accepts_choices():
    p = build_parser()
    assert p.parse_args(["scan", "--stdio", "x"]).target_os == "all"
    assert p.parse_args(["scan", "--stdio", "x", "--target-os", "auto"]).target_os == "auto"
    with pytest.raises(SystemExit):
        p.parse_args(["scan", "--stdio", "x", "--target-os", "bsd"])


def test_target_os_is_reported_in_scan_metadata():
    doc = to_json(ScanResult(target="t", transport="stdio", target_os="posix"))
    assert '"target_os": "posix"' in doc
