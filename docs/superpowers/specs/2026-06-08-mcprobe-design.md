# mcprobe - Design Spec

**Date:** 2026-06-08
**Author:** Dennis Sepede (Den-Sec)
**Status:** Approved design, pre-implementation
**Repo (planned):** `Den-Sec/mcprobe` (public, MIT)

---

## 1. Context & problem

MCP (Model Context Protocol) servers expose **tools** that take model-influenced input and route it to real sinks: shells, HTTP clients, file systems, databases. When a tool handler passes a parameter to a dangerous sink without proper handling, the server is exploitable - command injection, SSRF, path traversal, SQLi, auth bypass, info leak - regardless of how "safe" the tool *description* looks.

The existing MCP security ecosystem does **not** cover this well:

- **Defensive / config scanners** (Snyk-Invariant `mcp-scan`, Cisco `mcp-scanner`, `ressl/mcpwn`) analyze *tool descriptions / metadata* for poisoning, rug-pull, excessive scope. They protect the **client** from malicious servers; they do not exploit the server's own handler code.
- **Vulnerable labs** (`harishsg993010/damn-vulnerable-MCP-server`, `IntegSec/VulnerableMCP`, `canack/bad-mcp`) are intentionally-vulnerable **targets**, not scanners.
- **Generic fuzzers** (`Agent-Hellboy/mcp-server-fuzzer`, Penzzer) throw malformed input looking for crashes/protocol violations. No vuln-class awareness, no confirmation oracles.
- **The one real incumbent for active vuln scanning, `Teycir/Mcpwn`**, detects RCE/traversal/prompt-injection via in-band pattern matching + timing + *local-only* DNS OOB. See §3 for its concrete gaps.

**mcprobe fills the gap:** an active, confirmation-driven security scanner for MCP server *implementations*. Point it at a target server, it enumerates tools, actively probes each handler with vuln-class-aware payloads, and reports **only confirmed** findings - confirmed out-of-band where possible. "Burp Active Scan, for MCP."

A structural advantage: mcprobe speaks the MCP protocol **directly** (it is an MCP client, no LLM in the loop). Probes and timing are therefore **deterministic**, unlike LLM-mediated testing.

## 2. Goals & non-goals

**Goals**
- Detect and **confirm** real, exploitable vulnerabilities in MCP server tool handlers.
- Confirmation-first: minimize false positives; prefer out-of-band / time-based / canary oracles over pattern guessing.
- Support both **stdio** and **HTTP (streamable/SSE)** transports.
- VAPT-grade reporting (severity, evidence, reproduction, CWE).
- Safe by default (non-destructive oracles); explicit opt-in for aggressive payloads.

**Non-goals (v1)**
- Not a defensive/runtime firewall or a tool-description poisoning scanner (that space is saturated; may add light passive checks later).
- Not a generic crash fuzzer.
- Not an LLM-driven autonomous agent.
- No GUI; CLI + library only.

## 3. Differentiation (evidence-based)

Teardown of incumbents (2026-06-08):

| Capability | Teycir/Mcpwn | mcp-server-fuzzer | **mcprobe (this)** |
|---|---|---|---|
| Vuln-class-aware checks | RCE, traversal, prompt-inj | none (crash only) | RCE, SSRF, traversal, auth, info-leak (v1) |
| **Remote OOB confirmation** (Interactsh/Collaborator) | ❌ local DNS only | ❌ | ✅ **core differentiator** |
| SSRF | ❌ planned | ❌ | ✅ |
| Auth/authz bypass | ❌ planned | ❌ | ✅ |
| HTTP/SSE transport | ⚠️ stdio-centric | ✅ | ✅ first-class |
| Confirmed-only / confidence | partial | ❌ | ✅ |
| Report (JSON/SARIF/MD) | JSON/HTML/SARIF | CSV/HTML | console/JSON/SARIF/MD (VAPT) |

The lead differentiator is **true remote out-of-band confirmation** - confirming blind SSRF/RCE on remote servers via external callback infrastructure - which no current MCP scanner does. This is authentic to the author (built a Collaborator integration in `burp-mcp`).

**Honest risk:** Teycir/Mcpwn is MIT and active; gaps could close. mcprobe competes on execution and OOB/VAPT depth, not on an unassailable moat.

## 4. Architecture

Modular Python package. Components with single, testable responsibilities:

- **Connector** (`mcprobe/connect/`) - establishes an MCP session over stdio or HTTP/streamable using the official `mcp` SDK; performs handshake; enumerates tools (+ JSON schema), resources, prompts. Interface: `connect(target) -> Session`, `Session.list_tools()`, `Session.call_tool(name, args)`.
- **Injection-point mapper** (`mcprobe/inject/`) - given a tool's JSON schema, builds a *valid baseline* argument set (satisfies required fields/types) and enumerates injectable positions (string params, array items, nested objects). Output: list of `InjectionPoint(tool, json_path, base_args)`.
- **OOB service** (`mcprobe/oob/`) - the confirmation backbone. Pluggable backends: (a) **Interactsh** client for remote OAST callbacks; (b) built-in **local HTTP/DNS listener** for local targets. Issues per-probe correlation tokens; `poll(token) -> [Interaction]`.
- **Check plugins** (`mcprobe/checks/`) - one module per vuln class. Each implements a common interface: `generate(point) -> [Probe]` and `evaluate(probe, response, oob_ctx) -> Finding | None`. Easy to extend (community PRs).
- **Engine** (`mcprobe/engine.py`) - orchestrates: for each tool x check x injection point, render probe -> `call_tool` -> evaluate via oracle -> collect **confirmed** findings with a confidence level. Handles rate-limiting and concurrency.
- **Reporter** (`mcprobe/report/`) - renders findings to console (rich), JSON, SARIF (CI), and Markdown (VAPT-grade: title, severity, CWE, affected tool/param, payload, evidence, reproduction, remediation).
- **CLI** (`mcprobe/cli.py`) - `mcprobe scan --stdio "<cmd>"` or `--http <url> [--header ...]`, plus `--oob interactsh|local`, `--aggressive`, `--checks ...`, `--output ...`.

Data flow: `CLI -> Connector -> (enumerate) -> Mapper -> Engine(Checks + OOB) -> Reporter`.

## 5. Vulnerability checks

**v1 (all with confirmation oracles):**

| Check | Payload approach | Oracle |
|---|---|---|
| Command injection | shell metachars into string params | OOB callback (primary) + time-based (`sleep`) fallback |
| SSRF | callback URLs / internal targets into url-like params | OOB callback (Interactsh) |
| Path traversal | `../` sequences + known canary/sentinel paths | canary marker in response |
| Auth/authz bypass | call sensitive tools with no / manipulated auth on HTTP transport | success-vs-expected-deny differential |
| Secret / info leak | trigger error/verbose paths | response pattern (keys, tokens, `BEGIN PRIVATE KEY`, env dumps) - 2+ markers to reduce FP |

**v1.1+ roadmap:** SQLi (time + error based), MCP-specific passive checks (tool-description poisoning, excessive scope, rug-pull hash pinning), insecure deserialization, schema pollution.

**Intended-vs-unintended nuance:** a tool *designed* to run commands (e.g. an explicit shell tool) is not itself a finding. mcprobe flags a sink reached through a parameter that should not reach it, and labels confirmed reachability + the unexpected sink. Findings carry this context.

## 6. Safety & ethics

- **Non-destructive by default:** v1 oracles (OOB callback, time-based, canary read) do not mutate or delete data.
- `--aggressive` opt-in for payloads that may have side effects; documented clearly.
- Authorization banner on run; README disclaimer: authorized testing only.
- Rate-limiting and concurrency caps to avoid DoS-ing the target.
- No exfiltration of real target data beyond what is needed to evidence a finding.

## 7. Testing strategy

- **Unit tests** per component (mapper schema handling, oracle correlation, check payload/eval logic) with mocks.
- **Integration fixtures:** a tiny internal deliberately-vulnerable MCP server (`tests/fixtures/vuln_server/`) exposing one tool per vuln class - runs in CI, no external deps, deterministic.
- **End-to-end showcase:** validate against public vulnerable labs (`harishsg993010/damn-vulnerable-MCP-server`, `IntegSec/VulnerableMCP`) and document the confirmed catches in the README as proof it works on real targets (not committed as deps; run manually / optional CI job).
- Coverage target: >80% on core modules.

## 8. Repo layout

```
mcprobe/
  mcprobe/            # package
    connect/  inject/  oob/  checks/  report/
    engine.py  cli.py
  tests/
    fixtures/vuln_server/
  docs/superpowers/specs/      # this spec
  README.md  LICENSE(MIT)  pyproject.toml  .github/workflows/ci.yml
```

Dev working copy on `C:\Users\Dennis\dev\mcprobe` (Python venv on C:, never on the UNC NAS mount).

## 9. MVP definition of done (v1)

- Connector: stdio + HTTP working against a real MCP server.
- OOB: Interactsh + local listener; correlation + polling.
- 5 checks (§5 v1) each producing confirmed findings on the internal fixtures.
- Reporter: console + JSON + SARIF + Markdown.
- Safe-by-default; `--aggressive` gate.
- CI green (unit + fixture integration), >80% core coverage.
- README with install, usage, the differentiation table, and a confirmed-catch demo against a public lab.

## 10. Open questions / risks

- **Interactsh dependency:** rely on public OAST (`oast.fun`) vs self-host. v1: support public Interactsh with an option to point at a self-hosted instance.
- **HTTP auth models:** MCP HTTP auth is still stabilizing; v1 supports header/token injection; revisit as the spec evolves.
- **Incumbent catch-up:** monitor Teycir/Mcpwn; keep OOB + VAPT reporting depth as the durable edge.
