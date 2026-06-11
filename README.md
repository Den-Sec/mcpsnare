# mcprobe

**Active, confirmation-driven security scanner for MCP server implementations - Burp Active Scan, for MCP.**

mcprobe enumerates the tools exposed by a Model Context Protocol (MCP) server,
maps their parameters to injection points, fires targeted payloads, and reports
each finding with a **confidence level earned by a concrete oracle** - prioritising
actively-confirmed, exploitable issues over guesses.

## Why mcprobe

Most "MCP security" tooling is either a generic fuzzer (noisy, low-signal) or a
defensive/static analyzer (looks at config and source, never proves exploitability).
mcprobe is different:

- **Oracle-backed, not guesses.** Every finding is tied to a concrete signal: an
  **out-of-band (OOB)** callback, a **calibrated time** delay, a **canary** value
  reflected in the response, or a **baseline diff**. No signal, no finding.
- **Graded, calibrated confidence.** Findings carry an explicit confidence level
  (**CONFIRMED / FIRM / TENTATIVE**, see [Confidence levels](#confidence-levels)).
  Per-tool baseline calibration suppresses the usual false-positive classes - a
  slow-but-safe tool, or output that merely looks secret-shaped, is not flagged.
- **Both transports.** Works against MCP servers over **stdio** (local process)
  and **streamable HTTP** (remote endpoint, with custom headers/auth).

## Install

```
pip install -e .
```

This installs the `mcprobe` console entry point.

## Usage

Scan a local stdio server:

```
mcprobe scan --stdio "python server.py"
```

Scan a remote HTTP MCP endpoint, with auth, emitting SARIF:

```
mcprobe scan --http https://host/mcp --header "Authorization: Bearer X" --output sarif
```

Useful flags:

- `--stdio "<cmd>"` launch the server as a subprocess and scan over stdio.
- `--http <url>` scan a streamable HTTP MCP endpoint.
- `--header "k:v"` add an HTTP header (repeatable).
- `--oob {local,interactsh,none}` confirmation backend for OOB callbacks
  (`local` default; `interactsh` requires an injectable interactsh client, see below).
- `--aggressive` also send blocking time-based (sleep) probes; by default mcprobe sends only non-blocking OOB/canary/pattern probes (time-based command-injection detection is aggressive-only).
- `--concurrency N` max concurrent probe requests (default 4). Time-based probes always run serially (uncontended latency).
- `--rate R` cap the request rate to R requests/second (default unlimited). Honored across concurrency and calibration.
- `--oob-timeout S` / `--oob-poll-interval S` tune how long (default 20s) and how often (default 2.5s) mcprobe polls for OOB callbacks.
- `--output {console,json,sarif,md}` output format (default `console`).

## Out-of-band (OOB) confirmation

OOB callbacks are how mcprobe confirms blind command injection and SSRF: a probe
makes the target reach back to a listener mcprobe controls.

- `--oob local` (default) spins up an in-process HTTP listener on localhost. It
  needs no external service and works for targets that can reach your machine
  (typically local stdio servers).
- `--oob interactsh` uses an out-of-band interaction server for targets that
  cannot reach localhost (e.g. remote HTTP servers). mcprobe's `InteractshOOB`
  is a thin, client-agnostic wrapper: it expects an injectable client object
  exposing `register() -> domain` and `poll() -> list`. You supply that client;
  any library implementing those two methods works. If no such client is
  installed, `--oob interactsh` errors gracefully and tells you to use
  `--oob local` instead. No specific pip package is bundled or required. See [docs/interactsh-runbook.md](docs/interactsh-runbook.md) for a real end-to-end runbook.
- `--oob none` disables OOB confirmation; only time-based and canary oracles run.

## Confidence levels

Every finding carries one of three confidence levels, each earned by a specific oracle:

| Level | Meaning | How it's earned |
| ---------- | --------------------------------------------------- | --------------- |
| **CONFIRMED** | The payload provably executed, or protected data was reached. | An out-of-band callback fired (cmd injection, SSRF), a canary value was read back (path traversal), or an unauthenticated call returned a response byte-identical to the authenticated one (auth bypass). |
| **FIRM** | A calibrated/inferred signal strongly indicates the issue, short of an OOB proof. | A response delay exceeds the per-tool calibrated baseline by the injected sleep (time-based cmd injection); a secret-shaped string appears in the probe response but not in the benign baseline (info leak); or an unauthenticated response matches the authenticated one only after stripping volatile fields like timestamps/ids (auth bypass). |
| **TENTATIVE** | Pattern-only match, with no calibration to corroborate it. | A secret-shaped string matched, but no baseline was available to prove the input triggered it - review manually. |

The OOB and canary checks emit only **CONFIRMED**. Auth-bypass emits **CONFIRMED**
on a byte-identical response or **FIRM** on a match after stripping volatile fields.
The timing and info-leak oracles are where **FIRM** and **TENTATIVE** arise.

## Checks

| Check            | Vulnerability                  | CWE      |
| ---------------- | ------------------------------ | -------- |
| `cmd_injection`  | OS command injection           | CWE-78   |
| `ssrf`           | Server-side request forgery    | CWE-918  |
| `path_traversal` | Path traversal                 | CWE-22   |
| `auth_bypass`    | Missing authentication         | CWE-306  |
| `info_leak`      | Secret / sensitive info leak   | CWE-200  |
| `sql_injection`  | SQL injection                  | CWE-89   |

mcprobe also enumerates MCP **resource templates** and treats their templated URI
params (e.g. `file:///{path}`) as injection points for path-traversal and info-leak.

## Authorized testing only

**mcprobe is an active scanner. It sends real, potentially destructive payloads
to the target.** Run it only against systems you own or have explicit written
authorization to test. Unauthorized use may be illegal. You are responsible for
how you use this tool.

## Validation

mcprobe is validated by an automated test suite against bundled
deliberately-vulnerable fixture servers in `tests/fixtures/`. The suite exercises
command injection (including cross-OS cmd.exe / PowerShell payloads), SSRF, path
traversal, info-leak, nested/array/enum injection points, and the OOB,
baseline-calibration, and false-positive-suppression paths end to end. See
[docs/claims-matrix.md](docs/claims-matrix.md) for the claim-to-test mapping.

It has also been smoke-tested against the real `@modelcontextprotocol/server-everything`
reference server (13 tools, 2 resource templates) - clean run, zero false positives. See
[docs/smoke-run.md](docs/smoke-run.md).

## Roadmap

- MCP-specific checks: tool-poisoning / prompt-injection via tool descriptions,
  and tool-scope / permission-boundary violations.
- Additional OOB providers and richer time-based oracles.

## License

MIT - see [LICENSE](LICENSE).
