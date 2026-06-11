"""In-process streamable-HTTP server harness for live-transport e2e tests.

Serves a FastMCP instance over real HTTP (uvicorn in a daemon thread, on an
ephemeral 127.0.0.1 port) and yields the streamable-HTTP endpoint URL, so a test
can scan it through mcprobe's real ``http_session`` - the same client path a user
hits with ``mcprobe scan --http``. stdio is already e2e-tested; this closes the
live-HTTP gap (see docs/claims-matrix.md).

A FastMCP instance binds a single ``StreamableHTTPSessionManager`` whose ``run()`` is
single-call, so ``streamable_http_app()`` must be served only ONCE per instance per
process. Tests therefore share one server (module-scoped fixture) and open their own
client sessions - which also mirrors a real deployment: one server, many clients.
"""
import logging
import threading
import time
from contextlib import contextmanager

import uvicorn

# mcprobe prints (it does not use logging), so muting the server-side stack only
# silences uvicorn/mcp internals - it keeps a test's captured stdout clean for JSON
# parsing (Task 4 reads the CLI's stdout) without suppressing anything mcprobe emits.
logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
logging.getLogger("mcp").setLevel(logging.CRITICAL)

_POLL_INTERVAL = 0.02  # 20ms between server-started polls


@contextmanager
def serve_streamable_http(mcp, ready_timeout=10.0):
    """Run ``mcp.streamable_http_app()`` under uvicorn in a background thread and
    yield the base MCP endpoint URL (e.g. ``http://127.0.0.1:<port>/mcp``).

    Binds an ephemeral port (``port=0``) and reads the real bound port back once the
    server reports ``started`` (race-free - no bind/close/reuse window). Shuts the
    server down and joins the thread on exit. Serve a given FastMCP instance only
    once per process (see module docstring).
    """
    app = mcp.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=0,
                            log_level="critical", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        start = time.monotonic()
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError("HTTP MCP server thread exited before start (bind/startup failed)")
            if time.monotonic() - start > ready_timeout:
                raise RuntimeError("HTTP MCP server did not start in time")
            time.sleep(_POLL_INTERVAL)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
