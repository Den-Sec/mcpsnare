# mcprobe v1.1 M7 - Resources Surface + SQLi (P2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add the two optional P2 capabilities: a SQL-injection check (error-based + calibrated time) and a resources surface (enumerate MCP resource templates and treat their templated URI params as injection points for path-traversal / info-leak).

**Architecture:** SQLi is a new check mirroring cmd-injection's structure - non-blocking error-based quote probes (FIRM on a triggered SQL-error baseline-diff, TENTATIVE pattern-only) plus aggressive-only calibrated time-based probes (reusing `ctx.baseline`). Resources reuse the WHOLE existing engine via a `ResourceToolView` adapter that presents a session's resource templates as tool-like objects (a templated `{param}` becomes a string injection point; "calling" fills the template and `read_resource`s it), so injection_points + checks + oracles + concurrency all apply unchanged.

**Tech Stack:** Python 3.11+, `mcp` SDK (`list_resource_templates`, `read_resource`), pytest + pytest-asyncio.

**Covers PRD v1.1:** R-A6 (resources surface) + the deferred SQLi check. Both P2 / optional. After M7, the v1.1 roadmap (P0-P2) is complete.

---

## Execution notes
- Run tests: `.venv/Scripts/python.exe -m pytest -q` (and `-m "not slow"`).
- Commit author `Dennis Sepede <dennisepede@proton.me>`, NO trailer.
- Branch `main`. Commit after each task. Baseline: 102 tests pass.

---

## Task 1: SQL injection check (P2)

**Files:** Create `mcprobe/checks/sql_injection.py`; Modify `mcprobe/checks/__init__.py` (register); Test `tests/test_checks.py`; Modify `README.md` (checks table).

> Error-based: quote-breaking payloads; a SQL-error signature present in the probe response but NOT the benign baseline → FIRM (TENTATIVE pattern-only when no baseline). Time-based (aggressive-only): calibrated margin like cmd-injection → FIRM. CWE-89.

- [ ] **Step 1: Write failing tests.** Append to `tests/test_checks.py`:

```python
from mcprobe.checks.sql_injection import SqlInjection


def test_sqli_firm_on_error_signature_diff():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcprobe"}, "name")
    ctx = _ctx_with_baseline(0.1, response="ok normal output")
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    f = s.evaluate(probe, "ERROR: near \"'\": syntax error", ctx)
    assert f is not None and f.cwe == "CWE-89" and f.confidence.value == "firm"


def test_sqli_suppressed_when_error_in_baseline():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcprobe"}, "name")
    ctx = _ctx_with_baseline(0.1, response="SQL syntax error appears even on benign input")
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    assert s.evaluate(probe, "you have an error in your SQL syntax", ctx) is None


def test_sqli_tentative_error_without_baseline():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcprobe"}, "name")
    ctx = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")  # no baseline
    probe = [p for p in s.generate(point, ctx) if p.meta.get("error_based")][0]
    f = s.evaluate(probe, "Warning: mysql_fetch_array() expects", ctx)
    assert f is not None and f.confidence.value == "tentative"


def test_sqli_time_based_only_when_aggressive():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcprobe"}, "name")
    default = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")
    assert all(not p.meta.get("time_based") for p in s.generate(point, default))
    aggr = CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio", aggressive=True)
    assert any(p.meta.get("time_based") for p in s.generate(point, aggr))


def test_sqli_time_based_firm_on_calibrated_delay():
    s = SqlInjection()
    point = InjectionPoint("q", "name", {"name": "mcprobe"}, "name")
    ctx = _ctx_with_baseline(0.1)  # aggressive=True via helper
    tprobe = [p for p in s.generate(point, ctx) if p.meta.get("time_based")][0]
    tprobe.meta["elapsed"] = 5.1
    f = s.evaluate(tprobe, "", ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-89"
```

- [ ] **Step 2: Run, expect FAIL** (`ModuleNotFoundError: mcprobe.checks.sql_injection`).

- [ ] **Step 3: Create `mcprobe/checks/sql_injection.py`:**

```python
import re
from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

_SLEEP_SECONDS = 5
_LATENCY_MULT = 3

# Distinctive SQL error signatures across common engines.
_ERROR_SIGNS = re.compile(
    r"SQL syntax|SQLSTATE|ORA-\d{5}|mysql_fetch|mysql_num_rows|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"you have an error in your SQL|near \"[^\"]*\": syntax error|"
    r"PG::\w+Error|pg_query|psql:|SQLite3?::|Microsoft OLE DB|"
    r"ODBC SQL Server|Npgsql\.|System\.Data\.SqlClient",
    re.IGNORECASE,
)

# Non-blocking error-based payloads (always sent).
_ERROR_PAYLOADS = ("'", '"', "')", "' OR '1'='1")

# Blocking time-based payloads (~_SLEEP_SECONDS), aggressive-only. Covers MySQL,
# MSSQL, PostgreSQL.
_TIME_TEMPLATES = (
    "' OR SLEEP({n})-- ",
    "'; WAITFOR DELAY '0:0:{n}'-- ",
    "' OR pg_sleep({n})-- ",
)


@register
class SqlInjection:
    id = "sql_injection"

    def generate(self, point, ctx):
        probes = []
        for pl in _ERROR_PAYLOADS:
            probes.append(Probe(check=self.id, point=point, payload=pl,
                                args=point.set(pl), meta={"error_based": True}))
        if getattr(ctx, "aggressive", False):
            for tpl in _TIME_TEMPLATES:
                pl = tpl.format(n=_SLEEP_SECONDS)
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl),
                                    meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes

    def evaluate(self, probe, response, ctx):
        if probe.meta.get("time_based"):
            elapsed = probe.meta.get("elapsed", 0)
            sleep_s = probe.meta["threshold"]
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                margin = max(baseline.latency + sleep_s * 0.8, baseline.latency * _LATENCY_MULT)
                evidence = f"response delayed {elapsed:.1f}s vs baseline {baseline.latency:.1f}s (SQL sleep)"
            else:
                margin = sleep_s
                evidence = f"response delayed {elapsed:.1f}s (SQL sleep)"
            if elapsed >= margin:
                return self._finding(probe, Confidence.FIRM, evidence)
            return None
        # error-based
        if not _ERROR_SIGNS.search(response or ""):
            return None
        baseline = getattr(ctx, "baseline", None)
        if baseline is not None:
            if _ERROR_SIGNS.search(baseline.response or ""):
                return None  # error already in benign baseline = not triggered
            return self._finding(probe, Confidence.FIRM,
                                 "SQL error signature triggered by quote payload (absent in baseline)")
        return self._finding(probe, Confidence.TENTATIVE,
                             "SQL error signature matched (no baseline to corroborate)")

    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.HIGH, confidence=conf, cwe="CWE-89",
                       title=f"SQL injection in {probe.point.tool}.{probe.point.param_name}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Use parameterised queries / prepared statements; never concatenate input into SQL.")
```

- [ ] **Step 4: Register it.** In `mcprobe/checks/__init__.py`, the current line is:
```python
from mcprobe.checks import path_traversal, info_leak, cmd_injection, ssrf, auth_bypass  # noqa: F401
```
Change to:
```python
from mcprobe.checks import (path_traversal, info_leak, cmd_injection, ssrf, auth_bypass,  # noqa: F401
                            sql_injection)  # noqa: F401
```

- [ ] **Step 5: Run** `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k sqli -q` → PASS (5 tests). `test_all_v1_checks_registered` stays green (it asserts the v1 set is a SUBSET of REGISTRY, so adding sql_injection is fine).

- [ ] **Step 6: README checks table.** In `README.md`, add a row to the Checks table after `info_leak`:
```
| `sql_injection`  | SQL injection                  | CWE-89   |
```

- [ ] **Step 7: Full suite** `.venv/Scripts/python.exe -m pytest -q` → expect 107 (was 102; +5). Also `-m "not slow"` green.

- [ ] **Step 8: Commit**
```
git add mcprobe/checks/sql_injection.py mcprobe/checks/__init__.py tests/test_checks.py README.md
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): SQL injection check - error-based + calibrated time (CWE-89)"
```

---

## Task 2: Session resource methods + ResourceToolView adapter (R-A6 core)

**Files:** Modify `mcprobe/connect/session.py` (`list_resource_templates`, `read_resource`); Create `mcprobe/connect/resources.py` (`ResourceToolView`); Test `tests/test_session.py`.

> Add the two SDK resource calls to `Session`, and an adapter that makes a session's resource templates look like tools so the existing engine can scan them.

- [ ] **Step 1: Write failing tests.** Append to `tests/test_session.py`:

```python
def test_resource_tool_view_exposes_templates_as_tools():
    import asyncio
    from mcprobe.connect.resources import ResourceToolView

    class FakeRes:
        async def list_resource_templates(self):
            return [("read_file", "file:///{path}")]
        async def read_resource(self, uri):
            return f"read {uri}"

    view = ResourceToolView(FakeRes())
    tools = asyncio.run(view.list_tools())
    assert len(tools) == 1
    assert tools[0].input_schema["properties"]["path"]["type"] == "string"
    assert "path" in tools[0].input_schema["required"]
    # calling fills the template and reads the resource
    out = asyncio.run(view.call_tool(tools[0].name, {"path": "../../etc/passwd"}))
    assert out == "read file:///../../etc/passwd"


def test_session_read_resource_flattens_text():
    import asyncio
    from mcprobe.connect.session import Session

    class _C:
        text = "resource body"

    class _Resp:
        contents = [_C()]

    class _CS:
        async def read_resource(self, uri):
            return _Resp()
        async def list_resource_templates(self):
            class R:
                resourceTemplates = []
            return R()

    s = Session(_CS())
    assert asyncio.run(s.read_resource("file:///x")) == "resource body"
    assert asyncio.run(s.list_resource_templates()) == []
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Add the Session methods.** In `mcprobe/connect/session.py`, add two methods to the `Session` class (after `call_tool`):

```python
    async def list_resource_templates(self):
        resp = await self._cs.list_resource_templates()
        return [(t.name, t.uriTemplate) for t in resp.resourceTemplates]

    async def read_resource(self, uri):
        resp = await self._cs.read_resource(uri)
        parts = []
        for c in resp.contents:
            parts.append(getattr(c, "text", "") or "")
        return "\n".join(p for p in parts if p)
```

- [ ] **Step 4: Create `mcprobe/connect/resources.py`:**

```python
import re

from mcprobe.models import ToolInfo

_TMPL_PARAM = re.compile(r"\{([^}/]+)\}")


class ResourceToolView:
    """Presents an object's resource templates as tool-like objects so the existing
    engine (injection_points + checks + oracles) can scan resources. A templated
    ``{param}`` in a URI template becomes a string injection point; ``call_tool`` fills
    the template and ``read_resource``s it.

    The wrapped object must expose ``list_resource_templates() -> list[(name, uriTemplate)]``
    and ``read_resource(uri) -> str`` (mcprobe's Session does).
    """

    def __init__(self, session):
        self._session = session
        self._templates = {}  # tool_name -> uriTemplate

    async def list_tools(self):
        tools = []
        for name, tmpl in await self._session.list_resource_templates():
            params = _TMPL_PARAM.findall(tmpl)
            if not params:
                continue
            props = {p: {"type": "string"} for p in params}
            schema = {"type": "object", "properties": props, "required": params}
            tool_name = f"resource:{tmpl}"
            self._templates[tool_name] = tmpl
            tools.append(ToolInfo(name=tool_name, description=name, input_schema=schema))
        return tools

    async def call_tool(self, name, args):
        tmpl = self._templates[name]
        uri = tmpl
        for key, value in args.items():
            uri = uri.replace("{" + key + "}", str(value))
        return await self._session.read_resource(uri)
```

- [ ] **Step 5: Run** `.venv/Scripts/python.exe -m pytest tests/test_session.py -q` → PASS.
- [ ] **Step 6: Full suite** → expect 109 (was 107; +2).
- [ ] **Step 7: Commit**
```
git add mcprobe/connect/session.py mcprobe/connect/resources.py tests/test_session.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(connect): resource template enumeration + ResourceToolView adapter (R-A6)"
```

---

## Task 3: Resource scan e2e + CLI wiring + docs (R-A6 acceptance)

**Files:** Test `tests/test_engine.py`; Modify `mcprobe/cli.py` (scan resources too); Modify `README.md`, `docs/claims-matrix.md`.

> Prove a templated resource param yields a confirmed path-traversal finding through the real engine via `ResourceToolView`, and wire the CLI to scan resources alongside tools.

- [ ] **Step 1: Write the failing e2e test.** Append to `tests/test_engine.py`:

```python
from mcprobe.connect.resources import ResourceToolView


class FakeResourceSession:
    """A vulnerable resource template file:///{path} that 'reads' the path - returns a
    traversal canary when the path escapes, like a real path-traversal-vulnerable read."""
    async def list_resource_templates(self):
        return [("read_file", "file:///{path}")]
    async def read_resource(self, uri):
        return "root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in uri else "not found"


@pytest.mark.asyncio
async def test_engine_confirms_traversal_in_resource_template():
    view = ResourceToolView(FakeResourceSession())
    findings = await scan_session(view, oob=None, transport="stdio",
                                  check_ids=["path_traversal"])
    confirmed = [f for f in findings
                 if f.check == "path_traversal" and f.confidence.value == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].param == "path"   # the templated URI param is the injection point
```

- [ ] **Step 2: Run, expect PASS** (Tasks 1-2 already provide the machinery; this confirms the wiring):
`.venv/Scripts/python.exe -m pytest tests/test_engine.py::test_engine_confirms_traversal_in_resource_template -q`

> If it FAILS, do not weaken it. Diagnose: print the findings. Likely cause: the template param regex or the engine not treating the view's ToolInfo as scannable. Report BLOCKED with the printout.

- [ ] **Step 3: Wire the CLI to scan resources.** In `mcprobe/cli.py` `_run`, after each `findings = await scan_session(sess, ...)` for the stdio and http paths, also scan resources and extend findings. The cleanest: right after the tool scan in the `if args.stdio:` branch:
```python
                findings = await scan_session(sess, oob=oob, transport="stdio", aggressive=args.aggressive,
                                              concurrency=args.concurrency, rate=args.rate,
                                              oob_timeout=args.oob_timeout,
                                              oob_poll_interval=args.oob_poll_interval)
                from mcprobe.connect.resources import ResourceToolView
                findings += await scan_session(ResourceToolView(sess), oob=oob, transport="stdio",
                                               aggressive=args.aggressive, concurrency=args.concurrency,
                                               rate=args.rate,
                                               check_ids=["path_traversal", "info_leak"])
```
Apply the same `findings += await scan_session(ResourceToolView(sess), ...)` after BOTH http-path tool scans (the with-headers and no-headers branches), using `transport="http"` and the same `check_ids=["path_traversal", "info_leak"]`. (Resources are read via `read_resource`, not a shell/HTTP fetch, so cmd-injection/ssrf/auth-bypass don't apply - scoping to traversal + info-leak is correct and avoids wasted OOB probes.)

- [ ] **Step 4: README + matrix.** In `README.md`, add a sentence to the Checks section or a new short "Resources" note: `mcprobe also enumerates MCP **resource templates** and treats their templated URI params (e.g. \`file:///{path}\`) as injection points for path-traversal and info-leak.`
  In `docs/claims-matrix.md`, add a row: `| Resource templates scanned: templated URI param is a traversal injection point (R-A6) | \`test_resource_tool_view_exposes_templates_as_tools\`, \`test_engine_confirms_traversal_in_resource_template\` |` and bump the test count to the new total.

- [ ] **Step 5: Run** `.venv/Scripts/python.exe -m pytest -q` → expect 110 (was 109; +1). Also `-m "not slow"` green.
- [ ] **Step 6: Commit**
```
git add tests/test_engine.py mcprobe/cli.py README.md docs/claims-matrix.md
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat: scan MCP resource templates as injection surface (R-A6)"
```

---

## Definition of Done (M7)

- [ ] SQLi check: error-based (FIRM on baseline-diff, TENTATIVE pattern-only) + aggressive calibrated time-based (FIRM); CWE-89; registered; in the README checks table.
- [ ] R-A6: `Session.list_resource_templates`/`read_resource`; `ResourceToolView` presents templates as tools; a templated URI param is a confirmed traversal injection point end-to-end; CLI scans resources; docs updated.
- [ ] Full suite green; commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.
- [ ] **v1.1 roadmap (P0-P2) complete.**

## Self-review notes
- SQLi reuses the calibrated-timing (cmd-injection) and baseline-diff (info-leak) patterns, so its confidence labels are honest (FIRM calibrated/triggered, TENTATIVE pattern-only). Time-based probes are aggressive-gated (blocking) per R-E3 and run uncontended per R-E1.
- R-A6's adapter design means ZERO engine changes - resources flow through injection_points/checks/oracles/concurrency unchanged. The fixture simulates the vulnerable read deterministically (returns the canary on a traversal URI), consistent with the FakeSession-style engine tests; a real stdio resource-server e2e can follow.
- CLI scans resources with only path_traversal+info_leak (the only checks meaningful for a `read_resource` surface), avoiding wasted OOB/cmd/auth probes.
