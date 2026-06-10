import asyncio
import pytest
from mcprobe.models import ToolInfo
from mcprobe.engine import scan_session
import mcprobe.checks  # register checks

class FakeSession:
    async def list_tools(self):
        return [ToolInfo("read_doc", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})]
    async def call_tool(self, name, args):
        if "etc/passwd" in args.get("path", ""):
            return "root:x:0:0:root:/root:/bin/bash"
        return "ok"

@pytest.mark.asyncio
async def test_engine_confirms_traversal_end_to_end():
    findings = await scan_session(FakeSession(), oob=None, transport="stdio")
    assert any(f.check == "path_traversal" and f.confidence.value == "confirmed"
               for f in findings)


class FetchSession:
    """Tool with a 'url' param so SSRF generates an OOB probe."""
    async def list_tools(self):
        return [ToolInfo("fetch", "", {"type": "object",
                "properties": {"url": {"type": "string"}}, "required": ["url"]})]
    async def call_tool(self, name, args):
        return "ok"


class DelayedOOB:
    """Simulates a remote interactsh-style backend: the callback for a token
    only becomes visible after the in-loop probe round-trip completes, i.e. it
    is delivered asynchronously and only surfaces on a poll that happens later.
    interactions() therefore returns empty if polled inline (before the wait)
    and a hit once the deferred poll runs."""
    def __init__(self):
        self._delivered: set[str] = set()

    def new_token(self):
        import uuid
        token = uuid.uuid4().hex[:12]
        # The callback lands only after control returns to the event loop,
        # i.e. it is NOT visible to an inline (pre-wait) poll. call_soon runs
        # before the engine resumes from its single oob_wait sleep.
        asyncio.get_running_loop().call_soon(self._delivered.add, token)
        return token, f"http://oob.test/{token}"

    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self._delivered else []


@pytest.mark.asyncio
async def test_engine_defers_oob_eval_for_delayed_callback():
    # With deferral + a single oob_wait, the delayed callback is caught.
    findings = await scan_session(FetchSession(), oob=DelayedOOB(),
                                  transport="http", oob_wait=0)
    assert any(f.check in ("ssrf", "cmd_injection") and f.confidence.value == "confirmed"
               for f in findings)
