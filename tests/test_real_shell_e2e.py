"""Real-OS-shell OOB confirmation for cmd_injection.

The other cmd-injection e2e tests confirm against a *fake* shell (a fixture that inspects
the payload string and simulates a callback) - deterministic, but it never proves the
generated payloads actually execute in a real shell. This test closes that caveat: it
scans the vuln fixture's ``ping`` tool, which runs its argument through the REAL OS shell
(``subprocess.run(..., shell=True)`` -> cmd.exe on Windows, /bin/sh on POSIX), with a REAL
local OOB listener. A confirmed finding here means an injected payload really escaped the
command and called back over a socket.

Gated on a real ``curl`` being on PATH (the payload's outbound tool). Windows 10+/Server and
most Linux CI images ship one, so this runs on the CI matrix; it skips (never false-fails)
where curl is absent. Only localhost traffic (LocalOOB binds 127.0.0.1) - no external network.
"""
import shutil
import sys
from pathlib import Path

import pytest

from mcpsnare.connect.session import stdio_session
from mcpsnare.engine import scan_session
from mcpsnare.oob.local import LocalOOB
import mcpsnare.checks  # noqa: F401  (register checks)

_SERVER = str(Path(__file__).parent / "fixtures" / "vuln_server" / "server.py")

pytestmark = pytest.mark.skipif(shutil.which("curl") is None,
                                reason="needs a real curl on PATH (the payload's outbound tool)")


@pytest.mark.asyncio
async def test_cmd_injection_confirmed_via_real_os_shell():
    # ping runs `echo pinging <host>` through the real shell; an injected `& curl <oob>`
    # (cmd.exe) or `; curl <oob>` (sh) executes for real and hits the local listener.
    with LocalOOB() as oob:
        async with stdio_session([sys.executable, _SERVER]) as session:
            findings = await scan_session(session, oob=oob, transport="stdio",
                                          check_ids=["cmd_injection"],
                                          oob_poll_interval=0.1, oob_timeout=5.0)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1                       # deduped to one finding for (tool, param)
    assert confirmed[0].param == "host"
    assert confirmed[0].cwe == "CWE-78"
    assert "curl" in confirmed[0].payload            # the firing OOB payload is named
