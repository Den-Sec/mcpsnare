"""Deliberately vulnerable MCP server for mcprobe integration tests. Do not deploy."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-server")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host."""
    try:
        return subprocess.run(
            f"echo pinging {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except subprocess.TimeoutExpired:
        return "timeout"


@mcp.tool()
def read_doc(path: str) -> str:
    """Read a document."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError as e:
        return f"error: {e}"


@mcp.tool()
def whoami(user: str) -> str:
    """Return profile; leaks secrets on the magic value."""
    if user == "mcprobe-probe":
        return "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----\nMIIB"
    return f"user {user}"


if __name__ == "__main__":
    mcp.run()
