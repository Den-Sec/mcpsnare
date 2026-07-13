"""Deliberately vulnerable MCP server with a REAL code-eval sink. Do not deploy.

`run_code` is the exact anti-pattern the `code_injection` check confirms: a `code`
parameter that is `eval`/`exec`-ed unsandboxed (like `execute_revit_code`'s IronPython
`exec()`). It makes the check CI-testable without a Revit backend - a language-native OOB
payload really opens a socket to mcpsnare's local listener, and the arithmetic canary is
really evaluated and reflected. A benign call (`code="mcpsnare"`) raises NameError, so the
calibration baseline never contains the canary marker (keeps the baseline-diff honest).
"""
import io
from contextlib import redirect_stdout

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("code-server")


@mcp.tool()
def run_code(code: str) -> str:
    """Evaluate a Python snippet and return its result (DANGEROUS: real eval/exec)."""
    try:
        return str(eval(code))          # expression sink: return the evaluated value
    except SyntaxError:
        buf = io.StringIO()             # statement sink: capture what it prints
        try:
            with redirect_stdout(buf):
                exec(code)
        except Exception as e:
            return f"error: {e}"
        return buf.getvalue()
    except Exception as e:
        return f"error: {e}"


if __name__ == "__main__":
    mcp.run()
