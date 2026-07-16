"""A minimal TOOLS-ONLY MCP server (low-level SDK, no resources capability).

Most real-world MCP servers (sequential-thinking, filesystem, github, ...) are tools-only
and do NOT implement the optional `resources/templates/list` method - they answer
JSON-RPC "Method not found". FastMCP-based fixtures always register an (empty) resources
handler, so they never exercised that path; this fixture does, guarding the regression
where mcpsnare crashed the whole scan on such servers.
"""
import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server("tools-only")


@server.list_tools()
async def list_tools():
    return [types.Tool(
        name="echo",
        description="Echo the given text.",
        inputSchema={"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"]},
    )]


@server.call_tool()
async def call_tool(name, arguments):
    return [types.TextContent(type="text", text=f"echo {arguments.get('text', '')}")]


async def _main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_main)
