import sys

import pytest

from mcprobe.connect.session import http_session, stdio_session


@pytest.mark.asyncio
async def test_stdio_session_lists_and_calls_tools():
    cmd = [sys.executable, "tests/fixtures/vuln_server/server.py"]
    async with stdio_session(cmd) as sess:
        tools = await sess.list_tools()
        names = {t.name for t in tools}
        assert {"ping", "read_doc", "whoami"} <= names
        out = await sess.call_tool("ping", {"host": "example.com"})
        assert "pinging example.com" in out


def test_http_session_factory_exists():
    cm = http_session("http://127.0.0.1:9/mcp", headers={"Authorization": "Bearer x"})
    assert hasattr(cm, "__aenter__")


def test_call_tool_flattens_structured_content():
    import asyncio
    from mcprobe.connect.session import Session

    class _Text:
        text = "plain part"

    class _Resp:
        content = [_Text()]
        structuredContent = {"secret": "AKIAIOSFODNN7EXAMPLE"}

    class _CS:
        async def call_tool(self, name, args):
            return _Resp()

    out = asyncio.run(Session(_CS()).call_tool("t", {}))
    assert "plain part" in out
    assert "AKIAIOSFODNN7EXAMPLE" in out  # structured content reaches the oracles
