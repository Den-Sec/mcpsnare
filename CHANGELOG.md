# Changelog

All notable changes to mcpsnare are documented here. Versions follow a simple
0.x scheme (the public interface is not yet frozen).

## 0.5.0 - 2026-07-13 - "confirm the code sink + honest reports"

The passive lens *flagged* an `execute_revit_code`-style tool; the active checks could not
*confirm* it, because `cmd_injection`'s shell metacharacters are a SyntaxError inside a
language interpreter. And a bare `results: []` could not be told apart from "nothing was
actually tested". This release closes both.

### Added
- **Active code/eval-sink injection (`code_injection`, CWE-94).** Speaks the sink's
  language: injects language-native OOB payloads (CPython `urllib`, Python 2 / IronPython
  `urllib2`, Node `require('http')`) with a per-payload token, and an arithmetic canary
  (`7*7` -> `49`) whose evaluation is reflected in the response. **CONFIRMED** on an OOB
  callback, **FIRM** on the canary reflected and absent from the benign baseline,
  **TENTATIVE** on the canary with no baseline; a `time.sleep` time-based variant is
  `--aggressive`-only. Gates on code-shaped parameter names (`code`/`script`/`expression`/
  `eval`/`python`/`ironpython`/`snippet`/`formula`, not `query`/`command`). A new
  `tests/fixtures/code_server` (a real `eval`/`exec` sink) confirms it in CI - a payload
  really opens a socket to the local listener, no Revit needed.
- **`ScanResult` with scan metadata.** `scan_session` now returns a `ScanResult` carrying
  `target`, `transport`, `tools_discovered`, `tools_reachable`, `checks_executed`,
  `aggressive`, and `time_based_skipped` alongside the findings, so an empty report is
  distinguishable from an untested one. Reports gained a scan-metadata block (JSON `scan`,
  SARIF `invocations`/`properties`, Markdown "Scan metadata" + honesty notes); the CLI
  prints a one-line scan header. `ScanResult` is list-like (iterate/`len`/index/`== []`)
  and merges two passes via `+` (back-compatible with every existing caller).
- **Free-form container coverage (mapper).** Injection-point mapping now reaches values
  inside open maps - `additionalProperties`, a bare/typeless `dict`, and `list[dict]` - by
  synthesizing a canary key (`modify_element(parameters: dict)` now yields a
  `parameters.mcpsnare` injection point). Structured objects and `additionalProperties:false`
  are untouched, so no new noise on fixed schemas.
- **Unauthenticated-privileged-proxy note (`privileged_proxy`, CWE-306, INFO).** When the
  manifest declares a CRITICAL/HIGH capability and the scan reached the tools with no
  credential (local stdio, or HTTP with no auth header), the transport is the only access
  control - flagged for vetting. Consumes the `capability` lens output.

### Changed
- **Confidence-aware dedup.** For a given `(check, tool, param)` a later, stronger oracle
  (e.g. a deferred OOB CONFIRMED) now upgrades an earlier weaker finding (e.g. an inline
  canary FIRM) instead of being dropped by first-write-wins.

### Notes
- 46 new tests; suite is now 185 green. No breaking changes to callers or report consumers.

## 0.4.0 - 2026-07-13 - "passive vetting lens"

Active confirmation is blind to what a server *declares*. Scanning a real target
(`Demolinator/revit-mcp-server`, a thin MCP proxy whose `execute_revit_code` tool is an
unsandboxed IronPython `exec()`) returned **zero findings** — the active checks probe
parameters and need a live sink, so a proxy with the dangerous sink downstream (or no
backend running) reads as "secure". This release adds manifest-level lenses so an
adoption/vetting scan is honest.

### Added
- **Passive capability lens (`capability`).** Reads the tool manifest (name, description,
  schema) with **zero tool calls** and flags declared high-risk capability: arbitrary
  code/command execution (CRITICAL, CWE-94), filesystem write/link and destructive ops
  (HIGH, CWE-73/749), filesystem read and SSRF-capable fetch (MEDIUM, CWE-22/918).
  Name-verb gated to avoid description false positives; **FIRM** on multiple independent
  signals, **TENTATIVE** on one. Never **CONFIRMED** — a declared capability is not an
  exploit proof. On the revit target this turns a 0-finding report into 1 CRITICAL + 5 HIGH.
- **Passive tool-poisoning lens (`tool_poisoning`).** Flags imperative-injection phrasing
  ("ignore previous instructions"), invisible/bidirectional unicode, and embedded URLs in
  tool/parameter descriptions (fed verbatim to the driving LLM). CWE-94, TENTATIVE.
- **Backend-reachability note (`reachability`).** When ≥80% of probed tools return
  connection-error-shaped baselines, the scan emits one INFO finding so an empty
  active-scan result is not misread as "secure" ("empty ≠ secure").
- New passive-check plumbing: `PassiveCheck` protocol + `PASSIVE_REGISTRY` /
  `register_passive` in `checks/base.py`, run once per tool from the manifest in
  `scan_session` before any active probing. No change to the `Finding` model or renderers.

### Notes
- 20 new tests (`tests/test_passive.py` + engine wiring in `tests/test_engine.py`);
  suite is now 139 green. Passive findings flow through the existing dedup/report path.

## 0.3.0 - 2026-06-11 - "mcpsnare"

First PyPI release. The project is renamed and the HTTP transport is now fully
end-to-end tested.

### Changed
- **Rebrand: mcprobe -> mcpsnare.** The tool, package, CLI command, and module are now
  `mcpsnare`; this is its PyPI debut (`pip install mcpsnare`). The repository moved to
  `Den-Sec/mcpsnare` and the old GitHub URLs redirect. No scanner behaviour changed.
- **MCP SDK migration.** Moved off the deprecated `streamablehttp_client` to
  `streamable_http_client` via `create_mcp_http_client`, which preserves the MCP read /
  connect timeouts. Same transport, current SDK surface.

### Added
- **Live HTTP transport e2e.** The test suite now spins an in-process streamable-HTTP
  MCP server (uvicorn, ephemeral localhost port) and scans it through the real
  `http_session`: a list+call round-trip, a confirmed path-traversal scan, a confirmed
  auth-bypass via a dual real-session unauth differential, and a full `mcpsnare scan --http`
  CLI run. Closes the HTTP end-to-end caveat - stdio was previously the only e2e-tested
  transport. No production-code changes (test/coverage only).

## 0.2.0 - 2026-06-10 - "v1.1 hardening pass"

A depth/correctness/honesty overhaul: mcpsnare now reaches realistically-shaped MCP
schemas, calibrates per tool to kill false positives, confirms remote OOB for real,
and only claims what it can prove.

### Added
- **Schema-aware injection (R-A1/A2/A3).** Recurses JSON Schema for string leaves in
  nested objects, array items, and behind required enums; builds schema-valid baselines
  (enum/const/format/`$ref`); deep-sets payloads at structured `json_path`s.
- **Per-tool baseline calibration (R-B1).** Benign control calls learn each tool's
  latency floor + benign response, fed to the timing and info-leak oracles.
- **Confidence taxonomy.** Findings are graded **CONFIRMED / FIRM / TENTATIVE**, each
  earned by a specific oracle (see README).
- **Real out-of-band fidelity (R-C1/C2/C3).** Poll-until-hit with a bounded timeout;
  one OOB token per cmd-injection separator (the firing payload is named); a real,
  bundled interactsh client (RSA-OAEP / AES-256-CTR), live-verified against `oast.fun` -
  `--oob interactsh` works out of the box.
- **Cross-OS payloads (R-D1).** Windows `cmd.exe` (`&`, `|`, `ping`) and PowerShell
  (`iwr`, `curl.exe`, `Start-Sleep`) alongside POSIX, deduped.
- **Honest `--aggressive` (R-E3).** Default scans send only non-blocking probes;
  `--aggressive` adds the blocking time-based (sleep) probes.
- **Scale (R-E1/E2).** Bounded concurrency (`--concurrency`, per-tool contexts; time-based
  probes run serially/uncontended) and a `--rate` token-bucket throttle.
- **Embed-in-valid-value (R-A4)** to reach params behind format/content validation;
  **structured tool output (R-A5)** surfaced to oracles.
- **New checks/surfaces:** SQL injection (`sql_injection`, CWE-89, error-based +
  calibrated time); MCP **resource templates** scanned as injection points (R-A6).
- CLI flags: `--concurrency`, `--rate`, `--oob-timeout`, `--oob-poll-interval`,
  `--interactsh-server`. New dependency: `cryptography`.

### Changed
- **False-positive elimination (R-B2/B3).** Time-based oracle uses a calibrated relative
  margin (not a fixed 5s); info-leak fires only on a secret-shaped string absent from the
  benign baseline (FIRM), else TENTATIVE.
- **Robust auth-bypass (R-B4).** Tolerant compare strips volatile fields (timestamps/
  ids/nonces) - CONFIRMED on a byte-identical response, FIRM on a normalized match;
  record-ids are not stripped. The engine now awaits the unauthenticated call (fixes
  auth-bypass over real async HTTP).

### Honesty (R-F1)
- README claims audited against tests; "confirmed-only" / "public-labs" overclaims
  removed; a `docs/claims-matrix.md` maps every public claim to a passing test.
- Smoke-tested against the real `@modelcontextprotocol/server-everything` (13 tools,
  2 resource templates) - clean run, zero false positives (`docs/smoke-run.md`).

## 0.1.0 - 2026-06-08

Initial release: connector (stdio + HTTP), schema-naive injection mapper, 5 checks
(cmd-injection, SSRF, path-traversal, auth-bypass, info-leak), OOB/time/canary oracles,
multi-format reporters (console/JSON/SARIF/Markdown).
