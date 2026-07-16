# mcpsnare

**Active security scanner for MCP servers.** It pentests Model Context Protocol servers and confirms real, exploitable vulnerabilities — think Burp Suite's Active Scan, but pointed at an MCP server, not a website.

[![ci](https://github.com/Den-Sec/mcpsnare/actions/workflows/ci.yml/badge.svg)](https://github.com/Den-Sec/mcpsnare/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcpsnare.svg)](https://pypi.org/project/mcpsnare/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

mcpsnare enumerates the tools an MCP server exposes, fires targeted payloads at their
parameters, and reports **only what it can prove**. Every finding is tied to a concrete
oracle — an out-of-band callback, a reflected canary, a calibrated timing delay — and
carries a graded confidence level.

Most "MCP security" tools pattern-match configs and source code. mcpsnare **triggers the
vulnerability and catches the proof**: a `CONFIRMED` finding is exploitable, not theoretical.

For **adoption vetting**, mcpsnare adds a passive manifest lens that surfaces the dangerous
capabilities a server *declares* — even against a thin proxy or with no backend reachable
(see [Passive vetting lens](#passive-vetting-lens)).

> _(Formerly published as `mcprobe`.)_

## Demo

A default scan of a vulnerable MCP server — no config, one command:

```console
$ mcpsnare scan --stdio "python vulnerable_server.py"
[!] mcpsnare - authorized testing only.

6 finding(s):
  [HIGH]      Path traversal in read_doc.path         (confirmed)
  [HIGH]      Secret/info leak via whoami             (firm)
  [HIGH]      Path traversal in read_cfg.config.path  (confirmed)
  [HIGH]      Path traversal in read_many.paths[0]    (confirmed)
  [HIGH]      Path traversal in read_mode.path        (confirmed)
  [CRITICAL]  Command injection in ping.host          (confirmed)
```

That `CRITICAL` command injection is `confirmed` because the injected payload made the
target call back to a listener mcpsnare controls — an **out-of-band proof of execution**,
not a guess. The same scan as machine-readable JSON (or SARIF / Markdown):

```console
$ mcpsnare scan --stdio "python vulnerable_server.py" --output json
{
  "summary": { "critical": 1, "high": 5, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "check": "path_traversal", "tool": "read_doc", "param": "path",
      "severity": "high", "confidence": "confirmed", "cwe": "CWE-22",
      "title": "Path traversal in read_doc.path",
      "payload": "../../../../../../etc/passwd",
      "evidence": "root:x:0:0:root:/root:/bin/bash",
      "remediation": "Resolve and contain paths within an allowed base dir."
    }
    /* ... */
  ]
}
```

Every report also carries a **scan-metadata** block — target, transport, tools discovered vs.
reachable, checks run, whether `--aggressive` was set, and how many injection points skipped the
blocking time-based probes (JSON `scan`, SARIF `invocations`, a Markdown "Scan metadata" section).
So an empty `findings` is distinguishable from "nothing was actually tested."

## Install

```bash
pipx install mcpsnare        # isolated CLI (recommended)
# or
pip install mcpsnare
```

From source (development):

```bash
git clone https://github.com/Den-Sec/mcpsnare && cd mcpsnare
pip install -e ".[dev]"
```

Both install the `mcpsnare` console entry point. Requires Python 3.11+.

## Quickstart

```bash
# Local stdio server (launched as a subprocess)
mcpsnare scan --stdio "python server.py"

# Remote streamable-HTTP endpoint, with auth, emitting SARIF for code scanning
mcpsnare scan --http https://host/mcp --header "Authorization: Bearer X" --output sarif

# Add blocking time-based probes (off by default) and tune concurrency
mcpsnare scan --stdio "python server.py" --aggressive --concurrency 8
```

## Why mcpsnare

Most MCP security tooling is either a generic fuzzer (noisy, low-signal) or a
defensive/static analyzer (reads config and source, never proves exploitability).
mcpsnare is built around active confirmation:

- **Oracle-backed, not guesses.** Every finding is tied to a concrete signal: an
  **out-of-band (OOB)** callback, a **calibrated time** delay, a **canary** value
  reflected in the response, or a **baseline diff**. No signal, no finding.
- **Graded, calibrated confidence.** Findings carry an explicit confidence level
  (**CONFIRMED / FIRM / TENTATIVE**, see [Confidence levels](#confidence-levels)).
  Per-tool baseline calibration suppresses the usual false-positive classes — a
  slow-but-safe tool, or output that merely looks secret-shaped, is not flagged.
- **Reaches real schemas.** Maps injection points through nested objects, array items,
  and params gated behind required enums; builds schema-valid baselines so payloads
  actually reach the handler.
- **Both transports.** Works against MCP servers over **stdio** (local process) and
  **streamable HTTP** (remote endpoint, with custom headers/auth) — both exercised
  end-to-end in CI on Linux and Windows.

## Confidence levels

Every finding carries one of three confidence levels, each earned by a specific oracle:

| Level | Meaning | How it's earned |
| ---------- | --------------------------------------------------- | --------------- |
| **CONFIRMED** | The payload provably executed, or protected data was reached. | An out-of-band callback fired (cmd injection, SSRF), a canary value was read back (path traversal), or an unauthenticated call returned a response byte-identical to the authenticated one (auth bypass). |
| **FIRM** | A calibrated/inferred signal strongly indicates the issue, short of an OOB proof. | A response delay exceeds the per-tool calibrated baseline by the injected sleep (time-based cmd injection); a secret-shaped string appears in the probe response but not in the benign baseline (info leak); or an unauthenticated response matches the authenticated one only after stripping volatile fields like timestamps/ids (auth bypass). |
| **TENTATIVE** | Pattern-only match, with no calibration to corroborate it. | A secret-shaped string matched, but no baseline was available to prove the input triggered it — review manually. |

The OOB and path-traversal canary checks emit only **CONFIRMED**. Auth-bypass emits
**CONFIRMED** on a byte-identical response or **FIRM** on a match after stripping volatile
fields. The timing, info-leak, and code-injection arithmetic-canary oracles are where
**FIRM** and **TENTATIVE** arise (`code_injection` is CONFIRMED on an OOB callback, FIRM
when the `7*7`→`49` canary is reflected and absent from the baseline). The passive
`capability` and `tool_poisoning` lenses emit **FIRM** or **TENTATIVE** — a *declared*
capability is not an exploit proof — and never **CONFIRMED**.

## Checks

Active checks (probe a parameter, confirm via an oracle):

| Check            | Vulnerability                  | CWE      |
| ---------------- | ------------------------------ | -------- |
| `cmd_injection`  | OS command injection           | CWE-78   |
| `code_injection` | Code / eval-sink injection     | CWE-94   |
| `ssrf`           | Server-side request forgery    | CWE-918  |
| `path_traversal` | Path traversal                 | CWE-22   |
| `auth_bypass`    | Missing authentication         | CWE-306  |
| `info_leak`      | Secret / sensitive info leak   | CWE-200  |
| `sql_injection`  | SQL injection                  | CWE-89   |

`code_injection` speaks the sink's language: where `cmd_injection` sends shell metacharacters
(a `SyntaxError` inside a Python/IronPython/JS `eval`), it injects language-native payloads
(`urllib`/`urllib2`/`require('http')`) that call back out-of-band, plus an arithmetic canary
(`7*7` → `49`) reflected in the response — turning a *declared* `execute_code` tool from
flagged into **confirmed**. Injection points also reach values inside **free-form containers**
(`additionalProperties`, bare `dict`, `list[dict]`), so a `modify_element(parameters: dict)`
tool is probed, not skipped.

Passive checks (read the tool manifest, zero tool calls — see [Passive vetting lens](#passive-vetting-lens)):

| Check            | What it flags                                        | CWE               |
| ---------------- | ---------------------------------------------------- | ----------------- |
| `capability`     | Declared dangerous capability (code-exec, fs, destructive, SSRF) | CWE-94/73/749/22/918 |
| `tool_poisoning` | Prompt-injection / hidden-unicode / URLs in descriptions | CWE-94        |

mcpsnare also enumerates MCP **resource templates** and treats their templated URI
params (e.g. `file:///{path}`) as injection points for path-traversal and info-leak.

## Passive vetting lens

Active confirmation needs a live, reachable backend and a sink it can trip. When you are
**vetting an MCP server for adoption**, two things matter that active probing can miss: the
dangerous capabilities the server *declares*, and poisoned tool descriptions. mcpsnare adds
two **passive** checks that read the tool manifest (names, descriptions, schemas) with **zero
tool calls**, so they work even against a thin proxy or with no backend running:

- **`capability`** — flags tools whose manifest declares a high-risk capability: arbitrary
  code/command execution (CRITICAL), filesystem write/link and destructive operations (HIGH),
  filesystem read and SSRF-capable fetch (MEDIUM). Confidence is **FIRM** when several
  independent signals agree (name verb + description + parameter), else **TENTATIVE**.
- **`tool_poisoning`** — flags imperative-injection phrasing ("ignore previous instructions"),
  invisible/bidirectional unicode, and embedded URLs in tool/parameter descriptions, which the
  driving LLM reads verbatim.

Passive findings are **declared capabilities, not confirmed exploits** — they tell you *what to
vet*, never that the server is exploited. A scan also emits an INFO **`reachability`** note when
most tools return connection-error baselines, and an INFO **`privileged_proxy`** note when a
CRITICAL/HIGH capability is reached with no credential presented (local stdio, or HTTP with no auth
header) — a lead to vet whether app-layer auth actually gates invocation, not a claim that it
doesn't. So an empty active-scan result is never misread as "secure".

## Out-of-band (OOB) confirmation

OOB callbacks are how mcpsnare confirms blind command injection and SSRF: a probe
makes the target reach back to a listener mcpsnare controls.

- `--oob local` (default) spins up an in-process HTTP listener on localhost. It
  needs no external service and works for targets that can reach your machine
  (typically local stdio servers).
- `--oob interactsh` uses an out-of-band interaction server for targets that
  cannot reach localhost (e.g. remote HTTP servers). mcpsnare ships a real interactsh
  client (RSA-OAEP / AES-256-CTR), so this works out of the box against the public
  `oast.fun` (override with `--interactsh-server`); it was live-verified end to end.
  See [docs/interactsh-runbook.md](docs/interactsh-runbook.md).
- `--oob none` disables OOB confirmation; only time-based and canary oracles run.

## Flags

- `--stdio "<cmd>"` / `--http <url>` — target transport (one required).
- `--header "k:v"` — add an HTTP header (repeatable).
- `--oob {local,interactsh,none}` — OOB confirmation backend (`local` default).
- `--aggressive` — also send blocking time-based (sleep) probes; by default mcpsnare
  sends only non-blocking OOB/canary/pattern probes (time-based detection is aggressive-only).
- `--concurrency N` — max concurrent probe requests (default 4). Time-based probes run serially.
- `--rate R` — cap to R requests/second (default unlimited).
- `--oob-timeout S` / `--oob-poll-interval S` — how long (default 20s) / how often (default 2.5s) to poll for OOB callbacks.
- `--output {console,json,sarif,md}` — output format (default `console`).

## Authorized testing only

**mcpsnare is an active scanner. It sends real, potentially destructive payloads
to the target.** Run it only against systems you own or have explicit written
authorization to test. Unauthorized use may be illegal. You are responsible for
how you use this tool.

## Validation

mcpsnare is validated by an automated test suite (186 tests) against bundled
deliberately-vulnerable fixture servers in `tests/fixtures/`. The suite exercises
command injection (including cross-OS cmd.exe / PowerShell payloads), code/eval-sink
injection (OOB-confirmed against a real `eval` sink), SSRF, path traversal, info-leak,
SQL injection, nested/array/enum and free-form-container injection points, the passive
capability/tool-poisoning lenses and the reachability/privileged-proxy notes, and the OOB,
baseline-calibration, and false-positive-suppression paths end to end — over **both**
stdio and a live in-process streamable-HTTP server, on Linux and Windows in CI. See
[docs/claims-matrix.md](docs/claims-matrix.md) for the claim-to-test mapping.

It has also been smoke-tested against the real `@modelcontextprotocol/server-everything`
reference server (13 tools, 2 resource templates) — clean run, zero false positives. See
[docs/smoke-run.md](docs/smoke-run.md).

## Roadmap

- Tool-scope / permission-boundary checks (which tools a token may reach).
- Additional OOB providers and richer time-based oracles.
- Real-shell (cmd.exe / PowerShell) validation of the Windows command-injection payloads in CI.

## License

MIT — see [LICENSE](LICENSE).
