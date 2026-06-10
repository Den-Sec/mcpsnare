# mcprobe

**Active, confirmation-driven security scanner for MCP server implementations - Burp Active Scan, for MCP.**

mcprobe enumerates the tools exposed by a Model Context Protocol (MCP) server,
maps their parameters to injection points, fires targeted payloads, and reports
**only the vulnerabilities it can actively confirm**.

## Why mcprobe

Most "MCP security" tooling is either a generic fuzzer (noisy, low-signal) or a
defensive/static analyzer (looks at config and source, never proves exploitability).
mcprobe is different:

- **Confirmation oracles, not guesses.** Every finding is backed by a concrete
  signal: an **out-of-band (OOB)** callback, a **time-based** delay, or a
  **canary** value reflected in the response. If the oracle does not fire, no
  finding is emitted.
- **Confirmed-only findings.** The report contains exploitable issues, not
  "potential" ones. This keeps false positives out of your SARIF and your inbox.
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
  `--oob local` instead. No specific pip package is bundled or required.
- `--oob none` disables OOB confirmation; only time-based and canary oracles run.

## Checks (v1)

| Check            | Vulnerability                  | CWE      |
| ---------------- | ------------------------------ | -------- |
| `cmd_injection`  | OS command injection           | CWE-78   |
| `ssrf`           | Server-side request forgery    | CWE-918  |
| `path_traversal` | Path traversal                 | CWE-22   |
| `auth_bypass`    | Missing authentication         | CWE-306  |
| `info_leak`      | Secret / sensitive info leak   | CWE-200  |

## Authorized testing only

**mcprobe is an active scanner. It sends real, potentially destructive payloads
to the target.** Run it only against systems you own or have explicit written
authorization to test. Unauthorized use may be illegal. You are responsible for
how you use this tool.

## Validation

mcprobe is validated against the bundled deliberately-vulnerable fixture server
(`tests/fixtures/vuln_server/server.py`) and against public vulnerable MCP labs.
The fixture exercises command injection, path traversal, and information-leak
flows end to end.

## Roadmap

- SQL injection check.
- MCP-specific checks: tool-poisoning / prompt-injection via tool descriptions,
  and tool-scope / permission-boundary violations.
- Additional OOB providers and richer time-based oracles.

## License

MIT - see [LICENSE](LICENSE).
