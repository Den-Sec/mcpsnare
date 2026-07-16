import sys

import pytest

from mcpsnare.connect.session import http_session, stdio_session


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
    from mcpsnare.connect.session import Session

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


def test_resource_tool_view_exposes_templates_as_tools():
    import asyncio
    from mcpsnare.connect.resources import ResourceToolView

    class FakeRes:
        async def list_resource_templates(self):
            return [("read_file", "file:///{path}")]
        async def read_resource(self, uri):
            return f"read {uri}"

    view = ResourceToolView(FakeRes())
    tools = asyncio.run(view.list_tools())
    assert len(tools) == 1
    assert tools[0].input_schema["properties"]["path"]["type"] == "string"
    assert "path" in tools[0].input_schema["required"]
    out = asyncio.run(view.call_tool(tools[0].name, {"path": "../../etc/passwd"}))
    assert out == "read file:///../../etc/passwd"


def test_session_read_resource_flattens_text():
    import asyncio
    from mcpsnare.connect.session import Session

    class _C:
        text = "resource body"

    class _Resp:
        contents = [_C()]

    class _CS:
        async def read_resource(self, uri):
            return _Resp()
        async def list_resource_templates(self):
            class R:
                resourceTemplates = []
            return R()

    s = Session(_CS())
    assert asyncio.run(s.read_resource("file:///x")) == "resource body"
    assert asyncio.run(s.list_resource_templates()) == []


def test_list_resource_templates_tolerates_method_not_found():
    # A tools-only server (most real MCP servers) does not implement the optional
    # resources/templates/list method and answers "Method not found". mcpsnare must treat
    # that as "no resource templates", NOT crash the whole scan.
    import asyncio
    from mcpsnare.connect.session import Session
    from mcp.shared.exceptions import McpError
    from mcp.types import ErrorData, METHOD_NOT_FOUND

    class _CS:
        async def list_resource_templates(self):
            raise McpError(ErrorData(code=METHOD_NOT_FOUND, message="Method not found"))

    assert asyncio.run(Session(_CS()).list_resource_templates()) == []


def test_list_resource_templates_reraises_other_mcp_errors():
    # Only method-not-found is tolerated; a real error must not be silently swallowed.
    import asyncio
    from mcpsnare.connect.session import Session
    from mcp.shared.exceptions import McpError
    from mcp.types import ErrorData, INTERNAL_ERROR

    class _CS:
        async def list_resource_templates(self):
            raise McpError(ErrorData(code=INTERNAL_ERROR, message="boom"))

    with pytest.raises(McpError):
        asyncio.run(Session(_CS()).list_resource_templates())
