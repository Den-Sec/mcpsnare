# Changelog

All notable changes to mcprobe are documented here. Versions follow a simple
0.x scheme (the public interface is not yet frozen).

## 0.2.0 - 2026-06-10 - "v1.1 hardening pass"

A depth/correctness/honesty overhaul: mcprobe now reaches realistically-shaped MCP
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
