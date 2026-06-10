# mcprobe v1.1 M4 - OS-Aware Payloads + Honest --aggressive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cmd-injection probe Windows targets (cmd.exe + PowerShell) as well as POSIX, and make `--aggressive` truthful - by default sending only non-blocking confirmation probes (OOB) and only enabling the blocking time-based `sleep` probes when `--aggressive` is set.

**Architecture:** cmd-injection's payloads become two deduped cross-OS template matrices: `_OOB_TEMPLATES` (non-blocking, outbound-request payloads for POSIX / cmd.exe / PowerShell, each with its own token per M3) and `_SLEEP_TEMPLATES` (blocking delay payloads for the three shells). A new `CheckContext.aggressive` flag (plumbed by the engine from a `scan_session(aggressive=...)` param, wired to the CLI's existing `--aggressive`) gates the blocking sleep templates: default scans emit no `sleep`/`Start-Sleep`/`ping` probes (fast and gentle), `--aggressive` adds them.

**Tech Stack:** Python 3.11+, official `mcp` SDK, pytest + pytest-asyncio (`asyncio_mode=auto`). Cross-OS OOB confirmation is proven with deterministic fake shell sessions (a fake that "executes" a recognized OS-specific OOB command by delivering its callback) - no real shells/network in the suite.

**Covers PRD v1.1 requirements:** R-D1 (cross-OS cmd-injection payloads, send-all-deduped per §8) and R-E3 (honest `--aggressive`). (R-E1/R-E2 concurrency + rate-limiting are P1 / M6 - explicitly OUT of M4.)

---

## Execution notes (read before starting)

- **Run tests with the project venv** (system Python lacks `pytest-asyncio`):
  `.venv/Scripts/python.exe -m pytest -q`  (and `-m "not slow"` to skip the ~36s slow test)
- **Commit author:** `Dennis Sepede <dennisepede@proton.me>`. **No trailer.** Use:
  `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`
- **Branch:** `main`. Commit after each task.
- **Baseline before starting:** 79 tests pass (78 + 1 `slow`). M1+M2+M3 complete and pushed.
- **Behavior change introduced by R-E3 (Task 1):** the blocking `sleep` time-based probes are NO LONGER emitted by default - only with `aggressive=True`. Several existing tests assume sleep probes exist; Task 1 updates them to pass `aggressive=True`. This is the intended change (it makes the M2 timing-FP proof an EXPLICIT aggressive-mode test, not a vacuous default-mode one).
- **Send-all-deduped (PRD §8 decision):** no `--target-os` hint in v1.1; the full deduped matrix is always sent. Auto-detect is deferred.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `mcprobe/checks/base.py` | `CheckContext` gains `aggressive: bool = False`. | **Modify** (Task 1) |
| `mcprobe/engine.py` | `scan_session(aggressive=False)` plumbs the flag into `CheckContext`. | **Modify** (Task 1) |
| `mcprobe/cli.py` | Wire the existing `--aggressive` flag into all `scan_session(...)` calls; honest help text. | **Modify** (Task 1) |
| `mcprobe/checks/cmd_injection.py` | Task 1: gate the sleep loop on `ctx.aggressive`. Task 2: replace payloads with cross-OS `_OOB_TEMPLATES` + `_SLEEP_TEMPLATES`. | **Modify** (Tasks 1+2) |
| `tests/test_checks.py`, `tests/test_engine.py` | Unit + integration tests; update existing time-based tests to aggressive mode. | **Modify** (Tasks 1-3) |

---

## Task 1: Honest `--aggressive` gates blocking probes (R-E3)

**Files:**
- Modify: `mcprobe/checks/base.py` (add `aggressive` field)
- Modify: `mcprobe/engine.py` (`scan_session` param + plumb into `CheckContext`)
- Modify: `mcprobe/cli.py` (wire `--aggressive` into the 3 `scan_session` calls + honest help)
- Modify: `mcprobe/checks/cmd_injection.py` (gate the sleep loop)
- Test: `tests/test_checks.py`, `tests/test_engine.py`

- [ ] **Step 1: Write/adjust the tests**

First, in `tests/test_checks.py`, UPDATE the `_ctx_with_baseline` helper so baseline-driven time tests run in aggressive mode (sleep probes now require it). Its current definition is:

```python
def _ctx_with_baseline(latency, response=""):
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    return CheckContext(oob=None, transport="stdio",
                        baseline=ToolBaseline(latency=latency, response=response))
```

Change it to add `aggressive=True` (harmless for the info-leak tests that also use it):

```python
def _ctx_with_baseline(latency, response=""):
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    return CheckContext(oob=None, transport="stdio", aggressive=True,
                        baseline=ToolBaseline(latency=latency, response=response))
```

Next, UPDATE `test_cmdi_generates_oob_and_time_probes`: its ctx must be aggressive for the sleep assertion. Its current ctx line is:

```python
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(), transport="stdio")
```

Change to:

```python
    ctx = CheckContext(call_tool=lambda n, a: "", oob=FakeOOB(), transport="stdio", aggressive=True)
```

Next, UPDATE `test_cmdi_firm_on_time_delay`: it generates and picks a sleep probe, so it needs aggressive. Its current body builds a probe via `_ctx()`; change the generate call to use an aggressive ctx. The current test is:

```python
def test_cmdi_firm_on_time_delay():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.0
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"
```

Change the `ctx = ...` line to:

```python
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
```

Then APPEND two new tests to `tests/test_checks.py`:

```python
def test_cmdi_default_omits_blocking_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # aggressive=False
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    probes = c.generate(point, ctx)
    assert all(not p.meta.get("time_based") for p in probes)
    assert all("sleep" not in p.payload for p in probes)


def test_cmdi_aggressive_enables_sleep_probes():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    probes = c.generate(point, ctx)
    assert any(p.meta.get("time_based") for p in probes)
```

And APPEND one engine plumbing test to `tests/test_engine.py`:

```python
@pytest.mark.asyncio
async def test_engine_plumbs_aggressive_to_checks():
    captured = {}

    class SpyAgg:
        id = "spyagg"
        def generate(self, point, ctx):
            captured["aggressive"] = ctx.aggressive
            return []
        def evaluate(self, probe, response, ctx):
            return None

    from mcprobe.checks.base import REGISTRY
    REGISTRY["spyagg"] = SpyAgg()
    try:
        await scan_session(CountingSession(), oob=None, transport="stdio",
                           check_ids=["spyagg"], aggressive=True)
    finally:
        del REGISTRY["spyagg"]
    assert captured["aggressive"] is True
```

Finally, UPDATE the M2 slow-safe e2e `test_slow_safe_tool_no_time_based_fp` so it actually sends sleep probes (otherwise, with sleep now gated, it would pass vacuously). Its current `scan_session(...)` call is:

```python
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["cmd_injection"])
```

Change it to:

```python
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["cmd_injection"], aggressive=True)
```

- [ ] **Step 2: Run to verify failures**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi tests/test_engine.py -k aggressive -q`
Expected: FAIL - `CheckContext` has no `aggressive` field (`TypeError: unexpected keyword argument 'aggressive'`), and `scan_session` has no `aggressive` param.

- [ ] **Step 3: Add the `aggressive` field to CheckContext**

In `mcprobe/checks/base.py`, the current `CheckContext` is:

```python
@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None
    baseline: ToolBaseline | None = None
```

Add `aggressive` as the LAST field:

```python
@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None
    baseline: ToolBaseline | None = None
    aggressive: bool = False
```

- [ ] **Step 4: Plumb `aggressive` through the engine**

In `mcprobe/engine.py`, change the `scan_session` signature from:

```python
async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_poll_interval=2.5, oob_timeout=20.0, calibrate=True):
```

to (add `aggressive=False` at the end):

```python
async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_poll_interval=2.5, oob_timeout=20.0, calibrate=True,
                       aggressive=False):
```

And change the `ctx = CheckContext(...)` construction (near the top of the function) from:

```python
    ctx = CheckContext(oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth)
```

to:

```python
    ctx = CheckContext(oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth, aggressive=aggressive)
```

- [ ] **Step 5: Gate the sleep loop in cmd-injection**

In `mcprobe/checks/cmd_injection.py`, the current `generate` sleep loop is:

```python
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

Wrap it in an `aggressive` gate:

```python
        if getattr(ctx, "aggressive", False):
            for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
                pl = f"mcprobe{tpl}"
                probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

(Leave the OOB loop above it unchanged.)

- [ ] **Step 6: Wire `--aggressive` into the CLI**

In `mcprobe/cli.py`, update the `--aggressive` help text. The current line is:

```python
    s.add_argument("--aggressive", action="store_true", help="reserved for v1.1 (no effect yet)")
```

Change to:

```python
    s.add_argument("--aggressive", action="store_true",
                   help="also send blocking time-based (sleep) probes; default sends only non-blocking OOB/canary/pattern probes")
```

Then add `aggressive=args.aggressive` to ALL THREE `scan_session(...)` calls in `_run`. Change:

```python
                findings = await scan_session(sess, oob=oob, transport="stdio")
```
to:
```python
                findings = await scan_session(sess, oob=oob, transport="stdio",
                                              aggressive=args.aggressive)
```

Change:
```python
                        findings = await scan_session(sess, oob=oob, transport="http",
                                                      call_tool_unauth=sess_unauth.call_tool)
```
to:
```python
                        findings = await scan_session(sess, oob=oob, transport="http",
                                                      call_tool_unauth=sess_unauth.call_tool,
                                                      aggressive=args.aggressive)
```

Change:
```python
                    findings = await scan_session(sess, oob=oob, transport="http")
```
to:
```python
                    findings = await scan_session(sess, oob=oob, transport="http",
                                                  aggressive=args.aggressive)
```

- [ ] **Step 7: Run the cmd/aggressive tests + full suite**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi tests/test_engine.py -q`
Expected: PASS (the updated time tests, the two new gate tests, the engine plumbing test).

Run the full suite (the slow test now runs an aggressive cmd-injection scan of the 6s tool - takes ~36s):
Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 79; expect 82 - 3 new tests). Also confirm `-m "not slow"` stays green.

- [ ] **Step 8: Commit**

```bash
git add mcprobe/checks/base.py mcprobe/engine.py mcprobe/cli.py mcprobe/checks/cmd_injection.py tests/test_checks.py tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat: honest --aggressive gates blocking time-based probes (R-E3)"
```

---

## Task 2: Cross-OS cmd-injection payload matrix (R-D1)

**Files:**
- Modify: `mcprobe/checks/cmd_injection.py` (`_OOB_TEMPLATES` + `_SLEEP_TEMPLATES` module tuples; `generate` iterates them)
- Test: `tests/test_checks.py`

> Replace the inline POSIX-only payloads with deduped cross-OS matrices covering POSIX sh, Windows cmd.exe, and PowerShell. Each OOB payload still gets its own token (R-C2). The full matrix is always sent (send-all-deduped, PRD §8).

- [ ] **Step 1: Write/adjust the tests**

In `tests/test_checks.py`, UPDATE `test_cmdi_per_payload_tokens_identify_separator`: the OOB matrix grows from 3 to 6, so the hardcoded `== 3` must follow the matrix. Its current assertion is:

```python
    assert len({p.token for p in oob_probes}) == 3
```

Change it to assert all tokens are distinct (matrix-size-agnostic) plus a floor:

```python
    assert len({p.token for p in oob_probes}) == len(oob_probes)
    assert len(oob_probes) >= 6
```

(The `& curl` selection later in that test still works - `& curl {url}` remains in the matrix.)

Then APPEND two coverage tests to `tests/test_checks.py`:

```python
def test_cmdi_oob_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=PerPayloadOOB(), transport="stdio")
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "$(curl" in blob        # POSIX command substitution
    assert "| curl" in blob        # cmd.exe / POSIX pipe
    assert "iwr " in blob          # PowerShell Invoke-WebRequest
    assert "curl.exe " in blob     # PowerShell real curl


def test_cmdi_sleep_payloads_cover_posix_cmd_powershell():
    c = CmdInjection()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    point = InjectionPoint("run", "host", {"host": "mcprobe"}, "host")
    blob = " ".join(p.payload for p in c.generate(point, ctx))
    assert "sleep 5" in blob              # POSIX
    assert "Start-Sleep -s 5" in blob     # PowerShell
    assert "ping -n 6" in blob            # cmd.exe (no sleep builtin)
```

- [ ] **Step 2: Run to verify failures**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k "cover or per_payload" -q`
Expected: FAIL - current payloads have no `iwr`/`curl.exe`/`| curl`/`Start-Sleep`/`ping`, and `per_payload` expects only 3 OOB tokens.

- [ ] **Step 3: Add the matrices + iterate them in generate**

In `mcprobe/checks/cmd_injection.py`, add these module tuples right after the `_LATENCY_MULT = 3` line:

```python
# OOB confirmation payloads: each triggers an outbound request to {url}. Covers POSIX
# sh, Windows cmd.exe, and PowerShell, deduped. Non-blocking (always sent).
_OOB_TEMPLATES = (
    "; curl {url}",          # POSIX
    "$(curl {url})",         # POSIX command substitution
    "& curl {url}",          # cmd.exe / POSIX background
    "| curl {url}",          # cmd.exe / POSIX pipe
    "; iwr {url}",           # PowerShell (Invoke-WebRequest)
    "; curl.exe {url}",      # PowerShell (real curl, not the iwr alias)
)

# Blocking time-based payloads (~_SLEEP_SECONDS delay), sent only with --aggressive.
_SLEEP_TEMPLATES = (
    "; sleep {n}",                # POSIX
    "$(sleep {n})",               # POSIX command substitution
    "& ping -n {n1} 127.0.0.1",   # cmd.exe (no sleep builtin; ping ~1s/echo)
    "; Start-Sleep -s {n}",       # PowerShell
)
```

Then replace the body of `generate`. The current `generate` (after Task 1) is:

```python
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            for tpl in ("; curl {url}", "$(curl {url})", "& curl {url}"):
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        if getattr(ctx, "aggressive", False):
            for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
                pl = f"mcprobe{tpl}"
                probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

Replace it with (iterating the matrices):

```python
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            for tpl in _OOB_TEMPLATES:
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        if getattr(ctx, "aggressive", False):
            for tpl in _SLEEP_TEMPLATES:
                pl = f"mcprobe{tpl.format(n=_SLEEP_SECONDS, n1=_SLEEP_SECONDS + 1)}"
                probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

- [ ] **Step 4: Run the coverage + per-payload tests**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi -q`
Expected: PASS (coverage tests, updated per-payload-count test, and the existing OOB tests - `test_cmdi_generates_oob_and_time_probes` still finds `http://oob/tok123` and `sleep` in the aggressive ctx, `test_cmdi_confirmed_on_oob_hit` still confirms the first tokened probe).

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 82; expect 84). NOTE: the slow test now sends 4 sleep probes (POSIX×2 + ping + Start-Sleep) against the 6s tool, ~36s total - still `slow`-marked, no FP (the relative oracle suppresses all). Confirm `-m "not slow"` stays green.

- [ ] **Step 6: Commit**

```bash
git add mcprobe/checks/cmd_injection.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): cross-OS cmd-injection payloads (cmd.exe + PowerShell)"
```

---

## Task 3: Cross-OS OOB confirmation e2e (R-D1 acceptance)

**Files:**
- Test: `tests/test_engine.py` (two integration tests through `scan_session`)

> Prove R-D1's acceptance ("a PowerShell-backed vulnerable fixture is confirmed via OOB; a cmd.exe one too") deterministically: a fake "shell" session that confirms only the OS-specific OOB commands it recognizes, by delivering that payload's callback. No real shell or network.

- [ ] **Step 1: Write the failing integration tests**

Append to `tests/test_engine.py`:

```python
class ShellLikeOOB:
    """Records issued tokens+urls; a fake shell delivers a token's callback when it
    'executes' the matching payload."""
    def __init__(self):
        self.issued = {}      # token -> url
        self.delivered = set()
    def new_token(self):
        t = f"tok{len(self.issued) + 1}"
        url = f"http://oob/{t}"
        self.issued[t] = url
        return t, url
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self.delivered else []


def _shell_session(oob, recognizes):
    """A tool whose simulated shell 'executes' a payload (delivering its OOB callback)
    only if the payload contains one of `recognizes` (OS-specific command shapes)."""
    class _Sess:
        async def list_tools(self):
            return [ToolInfo("run", "", {"type": "object",
                    "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]})]
        async def call_tool(self, name, args):
            cmd = args.get("cmd", "")
            if any(r in cmd for r in recognizes):
                for tok, url in oob.issued.items():
                    if url in cmd:
                        oob.delivered.add(tok)
            return "ran"
    return _Sess()


@pytest.mark.asyncio
async def test_engine_confirms_powershell_oob():
    oob = ShellLikeOOB()
    sess = _shell_session(oob, recognizes=["iwr ", "curl.exe "])   # PowerShell-only shell
    findings = await scan_session(sess, oob=oob, transport="stdio", check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.05)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert ("iwr" in confirmed[0].payload) or ("curl.exe" in confirmed[0].payload)


@pytest.mark.asyncio
async def test_engine_confirms_cmd_exe_oob():
    oob = ShellLikeOOB()
    sess = _shell_session(oob, recognizes=["| curl ", "& curl "])  # cmd.exe-style shell
    findings = await scan_session(sess, oob=oob, transport="stdio", check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.05)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert ("| curl" in confirmed[0].payload) or ("& curl" in confirmed[0].payload)
```

- [ ] **Step 2: Run them (should PASS given Tasks 1+2)**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "powershell or cmd_exe" -q`
Expected: PASS. Mechanism: cmd-injection issues the 6 OOB payloads (each its own token); the fake PowerShell shell delivers the callbacks for the `iwr`/`curl.exe` payloads only (cmd.exe shell delivers `| curl`/`& curl`); the engine's poll loop sees those tokens resolve; evaluate confirms; dedup collapses to one finding whose payload is the OS-appropriate separator.

> Confirm-the-wiring tests. If one does NOT pass, do not weaken it. Diagnose by printing `[(f.confidence.value, f.payload) for f in findings]` and `oob.delivered`. Likely real causes: a recognized substring not present in any matrix payload (Task 2 template text drift), or the poll loop not evaluating deferred probes. Report BLOCKED with the printout if genuinely stuck.

- [ ] **Step 3: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 84; expect 86)

- [ ] **Step 4: Commit**

```bash
git add tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(oob): cross-OS (PowerShell + cmd.exe) OOB confirmation e2e"
```

---

## Definition of Done (M4)

- [ ] R-D1 met: cmd-injection sends a deduped cross-OS payload matrix (POSIX + cmd.exe + PowerShell) for both OOB and (aggressive) time-based probes; a PowerShell-shaped and a cmd.exe-shaped fixture are each confirmed via OOB.
- [ ] R-E3 met: a default scan emits NO blocking `sleep`/`Start-Sleep`/`ping` probes; `--aggressive` enables them; the CLI flag is wired and its help is honest.
- [ ] Full suite green with `.venv/Scripts/python.exe -m pytest -q` (and `-m "not slow"`); commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.

## Self-review notes (author)

- **Spec coverage:** R-D1 (Task 2 matrices + Task 3 cross-OS OOB acceptance), R-E3 (Task 1 gate + CLI). R-E1/R-E2 (concurrency/rate-limit) are P1 -> M6, explicitly out. ✓
- **Back-compat / behavior change:** R-E3 makes blocking probes opt-in; all existing time-based tests are updated to aggressive mode in Task 1 (incl. the M2 slow-safe e2e, which becomes a genuine aggressive-mode proof rather than vacuous). The no-baseline time-oracle fallback and OOB confirmation paths are unchanged. ✓
- **Type/name consistency:** `CheckContext.aggressive` (Task 1) consumed by `cmd_injection.generate` via `getattr(ctx, "aggressive", False)`; `scan_session(aggressive=...)` plumbs it; `_OOB_TEMPLATES`/`_SLEEP_TEMPLATES` named consistently (Task 2). ✓
- **Determinism:** cross-OS confirmation uses fake shell sessions that deliver callbacks by recognizing payload substrings - no real shell/curl/network, no wall-clock dependence. ✓
- **Cost honesty:** the slow test grows to ~36s (4 aggressive sleep probes against a real 6s tool); it stays `slow`-marked so `-m "not slow"` keeps the default loop ~15s. Sending the full matrix (no --target-os) is the PRD §8 decision. ✓
- **Real-shell caveat (carry):** the cross-OS payloads are validated for GENERATION + OOB-confirmation wiring, not executed against real cmd.exe/PowerShell in CI. A real-shell validation (does `& ping -n 6` actually delay on cmd.exe; does `; iwr` fire on PowerShell) belongs with the real-interactsh e2e in M6/R-C3. Noted for M5 honesty + M6.
