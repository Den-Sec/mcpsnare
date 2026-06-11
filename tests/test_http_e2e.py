"""Live streamable-HTTP transport e2e: scan a real in-process MCP server over the
same http_session path that `mcprobe scan --http` uses. Closes the HTTP caveat in
docs/claims-matrix.md - stdio was the only end-to-end-tested transport before.

The harness reuses the existing vulnerable FastMCP fixture, served over HTTP. All
tests share ONE server (module-scoped `live_url`): a FastMCP instance can be served
only once per process, and one-server/many-clients mirrors real usage."""
import io
import json
from contextlib import redirect_stdout

import pytest

from mcprobe.connect.session import http_session
from mcprobe.engine import scan_session
import mcprobe.checks  # noqa: F401  (register checks)
from tests.fixtures.http_server import serve_streamable_http
from tests.fixtures.vuln_server.server import mcp


@pytest.fixture(scope="module")
def live_url():
    """One in-process streamable-HTTP server shared by every test in this module.
    A FastMCP instance binds a single, single-call session manager, so tests must
    NOT each start their own server off the shared `mcp` singleton - they share this
    one and open their own client sessions."""
    with serve_streamable_http(mcp) as url:
        yield url


@pytest.mark.asyncio
async def test_http_server_round_trip_list_and_call(live_url):
    async with http_session(live_url, headers={"Authorization": "Bearer x"}) as sess:
        names = {t.name for t in await sess.list_tools()}
        assert {"ping", "read_doc", "whoami"} <= names
        out = await sess.call_tool("ping", {"host": "example.com"})
        assert "pinging example.com" in out


@pytest.mark.asyncio
async def test_scan_confirms_path_traversal_over_http(live_url):
    async with http_session(live_url, headers={"Authorization": "Bearer x"}) as sess:
        findings = await scan_session(sess, oob=None, transport="http",
                                      check_ids=["path_traversal"])
    confirmed = {(f.check, f.param) for f in findings if f.confidence.value == "confirmed"}
    assert ("path_traversal", "config.path") in confirmed   # nested object param
    assert ("path_traversal", "paths[0]") in confirmed       # array item param
    assert ("path_traversal", "path") in confirmed           # enum-gated tool (read_mode)


@pytest.mark.asyncio
async def test_scan_confirms_auth_bypass_over_http_dual_session(live_url):
    # Two REAL http_sessions to the same live server: one "authed" (sends a header),
    # one unauth (no header). The fixture enforces nothing, so the unauthenticated
    # differential fires - exercising the async call_tool_unauth path over a real
    # socket (a sync unauth call would crash on real HTTP; that was the M6 bug).
    async with http_session(live_url, headers={"Authorization": "Bearer x"}) as authed, \
               http_session(live_url, headers={}) as unauth:
        findings = await scan_session(authed, oob=None, transport="http",
                                      call_tool_unauth=unauth.call_tool,
                                      check_ids=["auth_bypass"], calibrate=False)
    assert any(f.check == "auth_bypass" and f.confidence.value == "confirmed"
               for f in findings)
