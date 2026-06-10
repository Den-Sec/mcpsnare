# mcprobe v1.1 M3 - OOB Fidelity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mcprobe's headline out-of-band confirmation actually catch delayed/remote callbacks and identify the exact payload that fired - by replacing the engine's single fixed OOB wait with a poll-until-hit loop (bounded by a timeout) and giving each cmd-injection OOB payload its own token.

**Architecture:** The engine drives OOB polling: after issuing all probes it repeatedly calls `oob.interactions(token)` for the outstanding deferred tokens every `oob_poll_interval` up to `oob_timeout`, exiting early once all outstanding tokens have resolved, then evaluates. No OOB provider interface change is needed - `interactions()` is already the poll primitive (LocalOOB reads its capture store; InteractshOOB polls the client on each call). cmd-injection issues one token per OOB separator so the confirming separator is identifiable in the finding's payload/evidence.

**Tech Stack:** Python 3.11+, official `mcp` SDK, pytest + pytest-asyncio (`asyncio_mode=auto`). OOB confirmation is tested with deterministic fake providers (user decision: no real interactsh/network in the suite - R-C3 real-interactsh e2e is P1/M6, out of M3).

**Covers PRD v1.1 requirements:** R-C1 (poll-until-hit OOB), R-C2 (per-payload OOB tokens). Success metric M-OOB. (R-C3 real interactsh verification is P1 / M6 - explicitly OUT of M3.)

---

## Execution notes (read before starting)

- **Run tests with the project venv** (system Python lacks `pytest-asyncio`):
  `.venv/Scripts/python.exe -m pytest -q`
- **Commit author:** `Dennis Sepede <dennisepede@proton.me>`. **No trailer.** Use:
  `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`
- **Branch:** `main` (working copy `C:\Users\Dennis\dev\mcprobe`). Commit after each task.
- **Baseline before starting:** 75 tests pass (74 + 1 `slow`). M1+M2 complete and pushed.
- **Backward-compat / behavior contracts that must stay true:**
  - The existing fixed `FakeOOB` in `tests/test_checks.py` returns the SAME `("tok123", "http://oob/tok123")` on every `new_token()`, so cmd-injection calling `new_token()` once per separator still yields all-`tok123` tokens and all payloads embedding that URL - `test_cmdi_generates_oob_and_time_probes` and `test_cmdi_confirmed_on_oob_hit` stay green.
  - `scan_session`'s `oob_wait` parameter is REPLACED by `oob_poll_interval` + `oob_timeout`. The one existing test that passes `oob_wait=0` (`test_engine_defers_oob_eval_for_delayed_callback`) is updated to the new params in Task 2.
  - The deferred-eval set is unchanged (token-bearing probes only); calibration/time/info-leak behavior from M2 is untouched.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `mcprobe/checks/cmd_injection.py` | One OOB token per separator payload; CONFIRMED evidence names the firing payload. | **Modify** |
| `mcprobe/engine.py` | Replace single `oob_wait` sleep with a poll-until-hit loop (`oob_poll_interval`, `oob_timeout`). | **Modify** |
| `tests/test_checks.py` | Unit test: per-payload tokens identify the firing separator. | **Modify** |
| `tests/test_engine.py` | Update the delayed-OOB test to new params; add late-callback-caught + timeout-bounded tests; add a combined R-C1+R-C2 integration test. | **Modify** |

---

## Task 1: Per-payload OOB tokens in cmd-injection (R-C2)

**Files:**
- Modify: `mcprobe/checks/cmd_injection.py` (`generate` OOB loop + CONFIRMED evidence in `evaluate`)
- Test: `tests/test_checks.py`

> Today all three OOB separators (`; curl`, `$(curl)`, `& curl`) share ONE token, so a confirmed callback can't be attributed to a specific separator. Give each its own token+URL. The CONFIRMED evidence string names the payload that fired.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_checks.py`:

```python
class PerPayloadOOB:
    """Issues a DISTINCT token per new_token() call; only the chosen token 'fires'."""
    def __init__(self):
        self._n = 0
        self.fired = None  # set to the token whose callback should resolve
    def new_token(self):
        self._n += 1
        t = f"tok{self._n}"
        return t, f"http://oob/{t}"
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token == self.fired else []


def test_cmdi_per_payload_tokens_identify_separator():
    c = CmdInjection()
    oob = PerPayloadOOB()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=oob, transport="stdio")
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    oob_probes = [p for p in c.generate(point, ctx) if p.token]
    # each OOB separator now gets its own token
    assert len({p.token for p in oob_probes}) == 3
    # simulate only the "& curl" separator's callback firing
    amp = [p for p in oob_probes if p.payload.startswith("mcprobe& curl")][0]
    oob.fired = amp.token
    confirmed = [c.evaluate(p, "", ctx) for p in oob_probes]
    confirmed = [f for f in confirmed if f]
    assert len(confirmed) == 1
    assert confirmed[0].payload == amp.payload          # exact separator identified
    assert "& curl" in confirmed[0].evidence            # evidence names it
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py::test_cmdi_per_payload_tokens_identify_separator -q`
Expected: FAIL - current code shares one token (`len({tokens})` == 1, not 3), and the CONFIRMED evidence is the fixed `"OOB callback received"` (no `& curl`).

- [ ] **Step 3: Update generate + evidence**

In `mcprobe/checks/cmd_injection.py`, replace the `generate` method's OOB block. The current `generate` is:

```python
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            token, url = ctx.oob.new_token()
            for tpl in (f"; curl {url}", f"$(curl {url})", f"& curl {url}"):
                pl = f"mcprobe{tpl}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

Replace it with (one `new_token()` per separator):

```python
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            for tpl in ("; curl {url}", "$(curl {url})", "& curl {url}"):
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

In the same file, in `evaluate`, change the CONFIRMED branch to name the payload. The current line is:

```python
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED, "OOB callback received")
```

Replace it with:

```python
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED,
                                 f"OOB callback received for payload {probe.payload!r}")
```

- [ ] **Step 4: Run the new test + the existing cmd-injection tests**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi -q`
Expected: PASS. (The fixed `FakeOOB` returns the same `tok123` on every call, so `test_cmdi_generates_oob_and_time_probes` - which asserts all OOB probes share `tok123` and embed `http://oob/tok123` - stays green; `test_cmdi_confirmed_on_oob_hit` still confirms.)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 75; expect 76)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/checks/cmd_injection.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): per-payload OOB tokens identify the firing separator"
```

---

## Task 2: Poll-until-hit OOB in the engine (R-C1)

**Files:**
- Modify: `mcprobe/engine.py` (replace the single `oob_wait` sleep with a polling loop; new params)
- Test: `tests/test_engine.py`

> Replace the single `await asyncio.sleep(oob_wait)` with a loop that polls the outstanding deferred tokens up to `oob_timeout` and exits early once all have resolved. This catches callbacks that land later than a fixed short wait, while a clean target is bounded by one timeout (not per-probe stalls).

- [ ] **Step 1: Write/adjust the failing tests**

First, UPDATE the existing `test_engine_defers_oob_eval_for_delayed_callback` in `tests/test_engine.py`. Its current last two lines are:

```python
    findings = await scan_session(FetchSession(), oob=DelayedOOB(),
                                  transport="http", oob_wait=0)
    assert any(f.check in ("ssrf", "cmd_injection") and f.confidence.value == "confirmed"
               for f in findings)
```

Change the `scan_session(...)` call to use the new params:

```python
    findings = await scan_session(FetchSession(), oob=DelayedOOB(),
                                  transport="http", oob_poll_interval=0.001, oob_timeout=0.1)
    assert any(f.check in ("ssrf", "cmd_injection") and f.confidence.value == "confirmed"
               for f in findings)
```

Then append two new tests to `tests/test_engine.py`:

```python
class CountResolveOOB:
    """A single-token OOB whose callback only becomes visible from the Nth
    interactions() call onward - simulating a remote callback that lands late."""
    def __init__(self, resolve_after):
        self.resolve_after = resolve_after
        self._calls = 0
        self._tok = None
    def new_token(self):
        self._tok = "tok"
        return self._tok, "http://oob/tok"
    def interactions(self, token):
        self._calls += 1
        return [{"path": "/tok"}] if (token == self._tok and self._calls >= self.resolve_after) else []


@pytest.mark.asyncio
async def test_engine_poll_catches_late_oob_callback():
    # Callback resolves only on the 5th poll; a generous timeout must still catch it.
    oob = CountResolveOOB(resolve_after=5)
    findings = await scan_session(FetchSession(), oob=oob, transport="http",
                                  check_ids=["ssrf"], oob_poll_interval=0.001, oob_timeout=1.0)
    assert any(f.check == "ssrf" and f.confidence.value == "confirmed" for f in findings)


@pytest.mark.asyncio
async def test_engine_poll_bounded_when_no_callback():
    # Callback never lands within budget -> clean target, no finding, bounded by timeout.
    oob = CountResolveOOB(resolve_after=10_000)
    findings = await scan_session(FetchSession(), oob=oob, transport="http",
                                  check_ids=["ssrf"], oob_poll_interval=0.001, oob_timeout=0.005)
    assert not any(f.check == "ssrf" for f in findings)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "delayed or poll" -q`
Expected: FAIL - `scan_session` does not accept `oob_poll_interval`/`oob_timeout` yet (`TypeError`).

- [ ] **Step 3: Replace the engine's deferred-eval block**

In `mcprobe/engine.py`, add `import math` to the imports at the top (next to `import asyncio`). The current import block is:

```python
import asyncio
import time
from mcprobe.inject.mapper import injection_points, build_baseline
from mcprobe.checks.base import REGISTRY, CheckContext
from mcprobe.models import ToolBaseline
```

Change it to:

```python
import asyncio
import math
import time
from mcprobe.inject.mapper import injection_points, build_baseline
from mcprobe.checks.base import REGISTRY, CheckContext
from mcprobe.models import ToolBaseline
```

Change the `scan_session` signature from:

```python
async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_wait=2.0, calibrate=True):
```

to:

```python
async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_poll_interval=2.5, oob_timeout=20.0, calibrate=True):
```

Replace the deferred-eval block at the end. The current block is:

```python
    if deferred:
        await asyncio.sleep(oob_wait)
        for check, probe, resp in deferred:
            collect(check.evaluate(probe, resp, ctx))
    return findings
```

Replace it with:

```python
    if deferred:
        # Poll-until-hit: outstanding OOB callbacks may land later than a fixed wait.
        # Poll every oob_poll_interval up to oob_timeout, exiting early once all
        # outstanding tokens have resolved. A clean target is bounded by one timeout.
        tokens = [p.token for _, p, _ in deferred if p.token]
        polls = max(1, math.ceil(oob_timeout / oob_poll_interval)) if oob_poll_interval > 0 else 1
        for _ in range(polls):
            if oob is not None and all(oob.interactions(t) for t in tokens):
                break
            await asyncio.sleep(oob_poll_interval)
        for check, probe, resp in deferred:
            collect(check.evaluate(probe, resp, ctx))
    return findings
```

- [ ] **Step 4: Run the updated + new engine tests**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "delayed or poll" -q`
Expected: PASS (delayed-callback caught, late-callback caught, no-callback bounded)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 76; expect 78). The M2 calibration/oracle tests are unaffected (they don't pass `oob_wait`).

- [ ] **Step 6: Commit**

```bash
git add mcprobe/engine.py tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(engine): poll-until-hit OOB confirmation with bounded timeout"
```

---

## Task 3: End-to-end R-C1+R-C2 integration (M-OOB)

**Files:**
- Test: `tests/test_engine.py` (one integration test through `scan_session`)

> Prove both pieces together through the real engine: a tool scanned with cmd-injection, OOB callbacks that land asynchronously (after the probe round-trip), confirmed via the poll loop, and the finding's payload naming the separator that fired.

- [ ] **Step 1: Write the failing integration test**

Append to `tests/test_engine.py`:

```python
class MultiDelayedOOB:
    """Per-payload tokens (R-C2); every issued token resolves asynchronously after the
    probe round-trip (R-C1) - i.e. NOT visible to an inline pre-poll check, only after
    the loop yields once."""
    def __init__(self):
        self._n = 0
        self._delivered = set()
    def new_token(self):
        self._n += 1
        t = f"tok{self._n}"
        asyncio.get_running_loop().call_soon(self._delivered.add, t)
        return t, f"http://oob/{t}"
    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self._delivered else []


class ShellSession:
    async def list_tools(self):
        return [ToolInfo("run", "", {"type": "object",
                "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]})]
    async def call_tool(self, name, args):
        return "ran"


@pytest.mark.asyncio
async def test_engine_confirms_cmd_oob_and_names_payload():
    findings = await scan_session(ShellSession(), oob=MultiDelayedOOB(), transport="stdio",
                                  check_ids=["cmd_injection"],
                                  oob_poll_interval=0.001, oob_timeout=0.5)
    confirmed = [f for f in findings
                 if f.check == "cmd_injection" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1                 # deduped to one finding per (tool, param)
    assert "curl" in confirmed[0].payload      # the firing OOB separator is named
```

- [ ] **Step 2: Run it to verify it passes (it should, given Tasks 1+2)**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py::test_engine_confirms_cmd_oob_and_names_payload -q`
Expected: PASS. (Mechanism: each separator gets its own token; all tokens are delivered via `call_soon` during the probe round-trips; the poll loop sees all resolved and exits early; evaluate confirms; dedup collapses to one cmd-injection finding whose payload is a `curl` separator.)

> This is a confirm-the-wiring test - if it does NOT pass, do not weaken it. Diagnose: print `[(f.check, f.confidence.value, f.payload) for f in findings]`. Likely real causes: per-payload tokens not distinct (Task 1 regressed), or the poll loop not evaluating deferred probes (Task 2). Report BLOCKED with the printout if genuinely stuck.

- [ ] **Step 3: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 78; expect 79)

- [ ] **Step 4: Commit**

```bash
git add tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(oob): e2e poll-until-hit + per-payload identification through scan_session"
```

---

## Definition of Done (M3)

- [ ] R-C1 met: the engine polls outstanding OOB tokens up to `oob_timeout` (default 20s) every `oob_poll_interval` (default 2.5s), exits early once all resolve; a late callback is caught and a clean target is bounded by one timeout.
- [ ] R-C2 met: each cmd-injection OOB separator carries its own token; a confirmed finding's payload/evidence names the exact firing separator.
- [ ] M-OOB met: an e2e through `scan_session` confirms a cmd-injection OOB finding whose evidence identifies the payload, with the callback delivered asynchronously.
- [ ] Full suite green with `.venv/Scripts/python.exe -m pytest -q`; commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.

## Self-review notes (author)

- **Spec coverage:** R-C1 (Task 2), R-C2 (Task 1), M-OOB e2e (Task 3). R-C3 (real interactsh verification) is P1 -> M6, explicitly out (deterministic fakes only, per user decision). ✓
- **No provider interface change:** `interactions()` already serves as the poll primitive for both LocalOOB (capture store) and InteractshOOB (polls client per call). The PRD's suggested `poll_all()` is an optimization deferred to M6 (real interactsh) - noted, not built now. Redundant per-token polling for interactsh is acceptable with fakes. ✓
- **Back-compat:** `oob_wait` removed; only one test used it, updated in Task 2. Fixed `FakeOOB` returns one token so existing cmd-injection unit tests stay green; new multi-token behavior is exercised by `PerPayloadOOB`/`MultiDelayedOOB`. ✓
- **Type consistency:** `oob_poll_interval`/`oob_timeout` named consistently across signature, tests, and plan; `math.ceil` import added. ✓
- **Determinism:** all OOB tests use count- or call_soon-based fakes (no wall-clock dependence, tiny intervals); the late-vs-timeout pair proves the timeout governs catch/miss without real delays. ✓
