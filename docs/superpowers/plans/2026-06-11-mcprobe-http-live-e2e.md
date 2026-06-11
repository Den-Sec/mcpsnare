# mcprobe - HTTP Transport Live e2e Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spin a real, in-process streamable-HTTP MCP server in the test suite and scan it through mcprobe's actual `http_session`, confirming real findings end-to-end - closing the "HTTP wired but not e2e-tested" caveat (stdio was the only end-to-end-tested transport).

**Architecture:** A reusable test harness (`serve_streamable_http`) runs `FastMCP.streamable_http_app()` under uvicorn in a daemon thread on an ephemeral localhost port and yields the `/mcp` endpoint URL. The *existing* vulnerable FastMCP fixture (`tests/fixtures/vuln_server/server.py`) is reused - served over HTTP instead of stdio, so the same vulnerable tools are exercised on both transports with zero new fixture code. All four tests share **one** server via a module-scoped `live_url` fixture and open their own client sessions: a FastMCP instance binds a single `StreamableHTTPSessionManager` whose `run()` is single-call, so serving the same instance twice in one process fails - and one-server/many-clients also mirrors a real deployment. The four tests scan that live server through the real `http_session`: (1) a list+call round-trip, (2) a confirmed path-traversal scan, (3) a confirmed auth-bypass via two real sessions (authed + unauth - the genuinely HTTP-specific path), and (4) a full `mcprobe scan --http` CLI run. No production code changes - this is a coverage/verification milestone that closes a documented gap.

**Tech Stack:** Python 3.11+, `mcp` SDK 1.27.x (`FastMCP.streamable_http_app()`), `uvicorn` + `starlette` (already hard transitive deps of `mcp`, present wherever mcprobe installs), `httpx` (mcprobe's `streamablehttp_client`), pytest + pytest-asyncio.

**Covers:** Carry-forward backlog item #1 (post-v1.1) from `personal_mcprobe.md` - "HTTP transport live e2e" + closing the HTTP caveat in `docs/claims-matrix.md`. Not a PRD requirement (PRD v1.1 is COMPLETE); this is a residual nice-to-have that hardens an honesty caveat into a tested claim.

---

## Execution notes
- Run tests: `.venv/Scripts/python.exe -m pytest -q` (the system Python lacks `pytest-asyncio`; ALWAYS use the `.venv`). `-m "not slow"` skips the one ~36s timing test.
- Commit author `Dennis Sepede <dennisepede@proton.me>`, **NO trailer**. Use `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`.
- Branch `main`. Commit after each task. **Baseline: 114 tests pass** (113 fast + 1 slow).
- All four new tests are fast (live localhost HTTP, sub-second each) - none get the `slow` marker.
- These mechanics were all pre-verified live against the running fixture server before this plan was written; if a step that says "expect PASS" fails, do NOT weaken the assertion - diagnose and report BLOCKED with the printout.

---

## Task 1: In-process streamable-HTTP server harness + live round-trip test

**Files:**
- Create: `tests/fixtures/http_server.py` (the harness)
- Create: `tests/test_http_e2e.py` (the live-HTTP test suite; this task adds the first test)

> The harness serves any `FastMCP` instance over real HTTP via uvicorn in a daemon thread on an ephemeral port (race-free `port=0` + readback) and yields the endpoint URL. The first test proves the harness + a real `http_session` round-trip (list_tools + call_tool over the live socket).

- [ ] **Step 1: Write the failing test.** Create `tests/test_http_e2e.py`:

```python
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
```

- [ ] **Step 2: Run, expect FAIL** (`ModuleNotFoundError: No module named 'tests.fixtures.http_server'`):

Run: `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py -q`
Expected: collection/import error - the harness module does not exist yet.

- [ ] **Step 3: Create the harness `tests/fixtures/http_server.py`:**

```python
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
```

> Note: no `tests/fixtures/__init__.py` is required - `tests.fixtures.vuln_server.server` already imports cleanly under pytest as a namespace package (verified), and `tests.fixtures.http_server` resolves the same way.

- [ ] **Step 4: Run, expect PASS:**

Run: `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py -q`
Expected: 1 passed. (A real uvicorn server starts, the SDK negotiates a `mcp-session-id`, tools list, `ping` echoes back, server tears down.)

- [ ] **Step 5: Full suite** `.venv/Scripts/python.exe -m pytest -q` → expect **115** (was 114; +1). Also `-m "not slow"` green (114 fast).

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/http_server.py tests/test_http_e2e.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(http): in-process streamable-HTTP harness + live list/call round-trip"
```

> **Post-review correction (applied):** the code-quality review caught that serving the *same* FastMCP instance twice in one process fails (its `StreamableHTTPSessionManager.run()` is single-call) - so the original per-test `with serve_streamable_http(mcp)` would make Tasks 2-4 hang `ready_timeout` then fail. Empirically reproduced (1st use passes, 2nd times out). Fixed by the module-scoped `live_url` fixture above (one shared server, many client sessions - also more realistic and faster), plus harness hardening (fast-fail on thread death, named poll interval). The unpushed Step 6 commit was amended in place to land the harness correct in one commit (same author, no trailer).

---

## Task 2: Confirmed path-traversal scan over live HTTP

**Files:**
- Modify: `tests/test_http_e2e.py` (append one test)

> Mirror of the stdio e2e `test_scan_confirms_nested_array_enum_traversal`, but over the real HTTP transport: prove that injection probes and the read-back canary traverse streamable HTTP correctly, confirming path-traversal on nested-object, array-item, and enum-gated params. The engine machinery already exists; this test confirms it works over the live socket.

- [ ] **Step 1: Write the test.** Append to `tests/test_http_e2e.py`:

```python
@pytest.mark.asyncio
async def test_scan_confirms_path_traversal_over_http(live_url):
    async with http_session(live_url, headers={"Authorization": "Bearer x"}) as sess:
        findings = await scan_session(sess, oob=None, transport="http",
                                      check_ids=["path_traversal"])
    confirmed = {(f.check, f.param) for f in findings if f.confidence.value == "confirmed"}
    assert ("path_traversal", "config.path") in confirmed   # nested object param
    assert ("path_traversal", "paths[0]") in confirmed       # array item param
    assert ("path_traversal", "path") in confirmed           # enum-gated tool (read_mode)
```

- [ ] **Step 2: Run, expect PASS:**

Run: `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py::test_scan_confirms_path_traversal_over_http -q`
Expected: PASS.

> If it FAILS, do NOT weaken it. Diagnose: print `[(f.check, f.param, f.confidence.value) for f in findings]`. The same scan passes over stdio (`test_scan_confirms_nested_array_enum_traversal`), so a divergence means the HTTP transport is dropping probes or responses - report BLOCKED with the printout.

- [ ] **Step 3: Full suite** `.venv/Scripts/python.exe -m pytest -q` → expect **116** (+1). `-m "not slow"` green.

- [ ] **Step 4: Commit**

```bash
git add tests/test_http_e2e.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(http): confirm path-traversal end-to-end over live streamable HTTP"
```

---

## Task 3: Confirmed auth-bypass over live HTTP (dual real sessions)

**Files:**
- Modify: `tests/test_http_e2e.py` (append one test)

> The genuinely HTTP-specific gap. `auth_bypass` is the only check gated on `transport == "http"`, and it needs a second session for the unauthenticated differential. The M6 carry-forward bug was that the unauth call was once invoked synchronously, which crashed on real HTTP (`Session.call_tool` is async). The existing `test_engine_auth_bypass_fires_over_async_unauth` proves the async-ness with a plain async stub - this test proves it against a *real socket*, with two live `http_session`s (authed + unauth) to the same server. The fixture enforces no auth, so the unauth response matches the authed one byte-for-byte → CONFIRMED.

- [ ] **Step 1: Write the test.** Append to `tests/test_http_e2e.py`:

```python
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
```

- [ ] **Step 2: Run, expect PASS:**

Run: `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py::test_scan_confirms_auth_bypass_over_http_dual_session -q`
Expected: PASS.

> If it FAILS, do NOT weaken it. Diagnose: print `[(f.check, f.tool, f.confidence.value) for f in findings]`. A crash inside `scan_session` (rather than an empty result) would point at the async unauth path over real HTTP - report BLOCKED with the traceback.

- [ ] **Step 3: Full suite** `.venv/Scripts/python.exe -m pytest -q` → expect **117** (+1). `-m "not slow"` green.

- [ ] **Step 4: Commit**

```bash
git add tests/test_http_e2e.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(http): confirm auth-bypass over live HTTP with dual real sessions"
```

---

## Task 4: Full CLI `--http` e2e + close the HTTP caveat in the docs

**Files:**
- Modify: `tests/test_http_e2e.py` (append one test)
- Modify: `docs/claims-matrix.md` (upgrade the HTTP rows, rewrite the HTTP known-limitation caveat, refresh the test count)
- Modify: `CHANGELOG.md` (add an `## [Unreleased]` entry)

> The real entrypoint `_run` is currently untested (only `build_parser` is). This test drives `mcprobe scan --http <url> --header ... --oob none --output json` against the live server, taking the dual-session branch (`cli.py` with-headers path: authed session + `call_tool_unauth`), and asserts both a single-session finding (path-traversal) and the dual-session finding (auth-bypass) appear in the JSON. Then close the documented HTTP caveat.

- [ ] **Step 1: Write the test.** Append to `tests/test_http_e2e.py`:

```python
@pytest.mark.asyncio
async def test_cli_http_scan_confirms_findings_json(live_url):
    # Drive the real CLI entrypoint (_run) over live HTTP with --header, so the
    # with-headers branch (authed + unauth dual session) runs end to end and emits
    # JSON. --oob none avoids starting a local OOB listener. Captures stdout (the
    # server stack is logging-silenced by the harness, so stdout is just the
    # banner + JSON).
    from mcprobe.cli import build_parser, _run
    args = build_parser().parse_args(
        ["scan", "--http", live_url, "--header", "Authorization:Bearer x",
         "--oob", "none", "--output", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        await _run(args)
    out = buf.getvalue()
    data = json.loads(out[out.index("{"):])   # skip the "[!] authorized testing" banner
    confirmed = {f["check"] for f in data["findings"] if f["confidence"] == "confirmed"}
    assert "path_traversal" in confirmed   # single-session probes traverse HTTP
    assert "auth_bypass" in confirmed       # dual-session unauth differential wired in the CLI
```

- [ ] **Step 2: Run, expect PASS:**

Run: `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py::test_cli_http_scan_confirms_findings_json -q`
Expected: PASS.

> If it FAILS, do NOT weaken it. Diagnose: print `out` (the captured stdout). A `ValueError` from `out.index("{")` means the banner/format changed; an empty `confirmed` set means the CLI http branch isn't wiring the dual session - report BLOCKED with the captured output.

- [ ] **Step 3: Update `docs/claims-matrix.md`.**

  (a) **Refresh the test count.** Line ~5 currently reads:
  ```
  mapping. Run the suite with `python -m pytest -q` (110 tests as of v1.1).
  ```
  Change `110` to `118`.

  (b) **Upgrade the transport rows.** Find this row in the "README claims → backing tests" table:
  ```
  | Streamable HTTP transport wired (session factory; CLI headers + auth/unauth differential) - see HTTP caveat below | `test_http_session_factory_exists`, `test_cli_parses_http_scan` |
  ```
  Replace it with these two rows:
  ```
  | Streamable HTTP transport wired (session factory; CLI parses `--http`/headers) | `test_http_session_factory_exists`, `test_cli_parses_http_scan` |
  | Works over streamable HTTP (exercised end-to-end against a live in-process MCP server): list+call round-trip, confirmed path-traversal, confirmed auth-bypass via dual-session unauth, full CLI `--http` scan | `test_http_server_round_trip_list_and_call`, `test_scan_confirms_path_traversal_over_http`, `test_scan_confirms_auth_bypass_over_http_dual_session`, `test_cli_http_scan_confirms_findings_json` |
  ```

  (c) **Rewrite the HTTP known-limitation caveat.** In the "Known limitations" section, find this bullet:
  ```
  - **HTTP transport is implemented and wired** (session factory, repeatable headers,
    and the auth/unauth differential for `auth_bypass` - whose async unauth path is now
    covered by `test_engine_auth_bypass_fires_over_async_unauth`) **but the automated
    suite does not yet spin a live HTTP MCP server for a full list+call round-trip.**
    stdio is the end-to-end-tested transport; a live-HTTP-server e2e is a follow-up.
  ```
  Replace it with:
  ```
  - **HTTP transport is end-to-end tested against a live, in-process streamable-HTTP
    MCP server** (uvicorn on an ephemeral localhost port): a real `http_session`
    list+call round-trip, a confirmed path-traversal scan, a confirmed auth-bypass via
    two real sessions (authed + unauth - exercising the async unauth differential over a
    real socket), and a full `mcprobe scan --http` CLI run - see `tests/test_http_e2e.py`.
    Residual: the server is a localhost in-process instance, not a remote network
    endpoint, so TLS, proxies, and real-world auth middleware are out of the suite's scope.
  ```

- [ ] **Step 4: Update `CHANGELOG.md`.** Insert an `## [Unreleased]` section directly above the `## 0.2.0 - 2026-06-10 - "v1.1 hardening pass"` heading:

```markdown
## [Unreleased]

### Added
- **Live HTTP transport e2e.** The test suite now spins an in-process streamable-HTTP
  MCP server (uvicorn, ephemeral localhost port) and scans it through the real
  `http_session`: a list+call round-trip, a confirmed path-traversal scan, a confirmed
  auth-bypass via a dual real-session unauth differential, and a full `mcprobe scan --http`
  CLI run. Closes the HTTP end-to-end caveat - stdio was previously the only e2e-tested
  transport. No production-code changes (test/coverage only).

```

- [ ] **Step 5: Full suite** `.venv/Scripts/python.exe -m pytest -q` → expect **118** (+1). Also `-m "not slow"` green (117 fast). Optionally sanity-check the docs reference real test names: `grep -o "test_[a-z_]*" docs/claims-matrix.md | sort -u` and confirm the four new names resolve in `tests/test_http_e2e.py`.

- [ ] **Step 6: Commit**

```bash
git add tests/test_http_e2e.py docs/claims-matrix.md CHANGELOG.md
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(http): full CLI --http e2e; close the HTTP live-server caveat"
```

---

## Task 5: No-header single-session CLI path over live HTTP (post-holistic-review completeness)

**Files:**
- Modify: `tests/test_http_e2e.py` (append one test)
- Modify: `docs/claims-matrix.md` (count 118 -> 119; extend the e2e row)

> Surfaced by the holistic review: Task 4's CLI test always passes `--header`, so it only exercises the CLI's DUAL-session branch (`cli.py` `if headers:`). The single-session NO-header branch (`else`: one session, no unauth differential) was untested e2e. This test closes it and proves the branch is distinct: path-traversal still confirms, but auth-bypass *cannot* (it structurally needs the unauth session, which only the `--header` branch opens).

- [ ] **Step 1: Append the test** to `tests/test_http_e2e.py` (after `test_cli_http_scan_confirms_findings_json`):

```python
@pytest.mark.asyncio
async def test_cli_http_scan_no_header_single_session(live_url):
    # The no-`--header` CLI path takes the single-session else branch (no unauth
    # differential). Proves that branch works over live HTTP AND is distinct from the
    # dual-session one: path-traversal still confirms, but auth-bypass cannot (it needs
    # the unauth session, which only the --header branch opens).
    from mcprobe.cli import build_parser, _run
    args = build_parser().parse_args(
        ["scan", "--http", live_url, "--oob", "none", "--output", "json"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        await _run(args)
    out = buf.getvalue()
    data = json.loads(out[out.index("{"):])
    confirmed = {f["check"] for f in data["findings"] if f["confidence"] == "confirmed"}
    assert "path_traversal" in confirmed       # single-session probes still traverse HTTP
    assert "auth_bypass" not in confirmed       # no unauth session -> no differential (distinct branch)
```

- [ ] **Step 2: Run, expect PASS.** `.venv/Scripts/python.exe -m pytest tests/test_http_e2e.py::test_cli_http_scan_no_header_single_session -q`. The negative assertion is a hard invariant (no `--header` -> `call_tool_unauth=None` -> `auth_bypass.generate` returns `[]`), not flaky.
- [ ] **Step 3: claims-matrix.md** - bump `118` -> `119`; append "(dual-session with `--header` and single-session without)" to the e2e row's claim and add `test_cli_http_scan_no_header_single_session` to its backing-tests list.
- [ ] **Step 4: Full suite** -> expect **119** (+1); `-m "not slow"` = 118.
- [ ] **Step 5: Commit** `test(http): cover the no-header single-session CLI path over live HTTP` (author `Dennis Sepede <dennisepede@proton.me>`, no trailer).

---

## Definition of Done

- [x] `tests/fixtures/http_server.py` serves any FastMCP instance over real streamable HTTP (uvicorn/daemon thread, race-free ephemeral port, clean teardown). Tests share ONE server via a module-scoped `live_url` fixture (FastMCP is single-serve per instance/process).
- [x] `tests/test_http_e2e.py` has five passing live-HTTP tests: round-trip, path-traversal CONFIRMED, auth-bypass CONFIRMED (dual real sessions), full CLI `--http` JSON scan (with `--header`), and the no-header single-session CLI path.
- [x] The HTTP caveat in `docs/claims-matrix.md` is rewritten from "not yet e2e-tested" to "e2e-tested against a live in-process server" with an honest residual; the transport claim row is backed by the five new tests; the test count is refreshed to 119.
- [x] `CHANGELOG.md` has an `## [Unreleased]` entry for the live HTTP e2e.
- [x] Full suite green (**119**; `-m "not slow"` = 118); all commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.
- [x] No production code changed (only `tests/` and `docs/` + CHANGELOG) - this is a verification/honesty milestone.

## Self-review notes

- **Reuse over new fixtures (DRY):** the harness serves the *existing* `vuln_server` FastMCP `mcp` object over HTTP. The same vulnerable tools are now exercised on both stdio and HTTP, with no second vulnerable server to maintain. The four tests parallel existing stdio/engine tests (`test_stdio_session_lists_and_calls_tools`, `test_scan_confirms_nested_array_enum_traversal`, `test_engine_auth_bypass_fires_over_async_unauth`) so the HTTP-vs-stdio behaviour is directly comparable.
- **Why a real socket, not an ASGI in-memory transport:** mcprobe's `streamablehttp_client` builds its own httpx client internally, so an in-memory `ASGITransport` can't be injected without monkeypatching the SDK. A localhost uvicorn server tests the *actual* client path a user hits - the honest "live" claim. The residual (localhost, not a remote/TLS endpoint) is disclosed in the caveat rather than overclaimed.
- **No `slow` marker (corrected estimate):** the original plan guessed "sub-second" - in reality the scan tests run ~10-12s each (path-traversal and both CLI scans do ~20+ streamable-HTTP round-trips with per-request session overhead; the round-trip and auth-bypass tests are ~1-2s). One shared module server keeps the file to ~25-35s aggregate. They are deliberately kept unmarked anyway: keeping them in the default suite means CI (ubuntu+windows × py3.11/3.12) runs the live-HTTP path on every cell - real cross-OS coverage of the transport, which a `slow` gate (ubuntu-3.11 only) would lose. If aggregate ever creeps too high, trim `check_ids` rather than slow-gating.
- **CI deps are guaranteed:** `uvicorn>=0.31.1` and `starlette>=0.27` are unconditional transitive deps of `mcp` (verified via `importlib.metadata.requires('mcp')`), so CI's `pip install -e ".[dev]"` already provides them - no new dependency to declare.
- **Determinism / output hygiene:** the harness silences the `uvicorn`/`mcp` loggers (mcprobe uses `print()`, not logging, so nothing mcprobe emits is suppressed). Task 4 therefore reads a clean banner-+-JSON stdout and parses from the first `{`. Port selection is race-free (`port=0` + readback), and teardown joins the daemon thread so a hung server can't wedge the suite.
- **Honesty discipline preserved:** every new claim in `claims-matrix.md` maps to a named passing test; the caveat is downgraded to a true residual (no remote/TLS/middleware coverage), not deleted. CHANGELOG entry states plainly that this is test/coverage only, no behaviour change.
- **Scope guard:** resources-over-HTTP is intentionally out of scope (the CLI's unconditional resource scan over HTTP is exercised incidentally in Task 4 and returns `[]` safely on the no-resource fixture; the resource engine logic is already e2e-tested via `FakeResourceSession`). Real-shell Windows execution and PyPI packaging remain separate backlog items.
```