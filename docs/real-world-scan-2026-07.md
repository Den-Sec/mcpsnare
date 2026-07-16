# Pointing mcpsnare at real MCP servers

*A honest field report — July 2026, mcpsnare 0.5.0*

mcpsnare is an active security scanner for MCP servers: it enumerates a server's tools,
fires real payloads at their parameters, and confirms vulnerabilities out-of-band (a probe
makes the target call back to a listener the scanner controls). Up to now it was validated
against its own bundled, deliberately-vulnerable fixtures and one smoke run. That is a weak
kind of proof. So I pointed it at a corpus of **real, official [`@modelcontextprotocol`](https://github.com/modelcontextprotocol/servers)
servers** and wrote down exactly what happened — including the parts that were embarrassing.

Two things happened. It **crashed on four of the six servers** (two robustness bugs, now
fixed), and it **confirmed a real SSRF** in the reference server. Here is the full account.

## Setup

Six official servers, launched over stdio via `npx`, scanned in default mode with a local
out-of-band listener:

```bash
mcpsnare scan --stdio "npx -y @modelcontextprotocol/server-<name> [args]" --oob local --output json
```

Default mode is deliberately conservative: it sends only non-blocking probes (OOB / canary /
pattern), so the blocking time-based injection probes are *not* run — mcpsnare says so in every
report, and an empty result is never "proof of secure". No credentials were provided, on
purpose: a credential-less scan is the realistic *adoption-vetting* case, and it is where the
passive manifest lens earns its keep.

## Part 1 — the bugs it found in itself first

The first run was humbling. Of six servers, **only two produced a clean report**. The other
four crashed. Two distinct root causes, both real, both now fixed — and both invisible to the
bundled fixtures.

**Bug 1 — crash on tools-only servers.** `sequential-thinking`, `filesystem`, and `github`
all aborted with an uncaught `McpError: Method not found`. Root cause: mcpsnare's resource-scan
pass unconditionally calls `resources/templates/list`, which is **optional** in the MCP spec.
A tools-only server — i.e. *most* real servers — legally answers "Method not found", and
mcpsnare let that abort the whole scan, discarding even the tools-pass findings it had already
computed. Why did the test suite never catch it? Every fixture is built on `FastMCP`, which
*always* registers a resources handler, so it always returns an empty list rather than
"Method not found". The one shape that matters in the wild was the one shape the fixtures
couldn't produce. Fixed: `Session.list_resource_templates()` now treats method-not-found as
"no resource templates" and continues (any other MCP error still propagates). A new low-level
tools-only fixture guards the regression in CI.

**Bug 2 — ugly failure when a server won't start.** `slack` refuses to start without its
credentials and exits before the MCP handshake. mcpsnare met that with a raw anyio
`ExceptionGroup` traceback. Fixed: the CLI now prints a clean `[!] Could not connect to the
target ...` and exits non-zero for connection/protocol failures — while still letting genuine
internal errors surface their traceback, so real bugs stay visible.

This is the whole argument for testing against reality: the toy targets were self-consistent
and green, and they hid two bugs that would have crashed the tool against the majority of real
servers. After the fixes, **five of six ran cleanly**; the sixth (`slack`) now *fails
gracefully* because it genuinely cannot start without credentials.

## Part 2 — the confirmed finding: SSRF in the reference server

`server-everything` is Anthropic's feature-demo server. It ships a tool
`gzip-file-as-resource` whose `data` parameter is documented as *"URL or data URI of the file
content to compress"* (`format: uri`). mcpsnare put its own OOB URL in that parameter, and the
listener received the callback:

```json
{
  "check": "ssrf",
  "tool": "gzip-file-as-resource", "param": "data",
  "severity": "high", "confidence": "confirmed", "cwe": "CWE-918",
  "payload": "http://127.0.0.1:52582/ed0f4560fb8a",
  "evidence": "OOB callback received",
  "remediation": "Validate/allowlist outbound URLs; block internal ranges & metadata IPs."
}
```

This is the point of active confirmation. A manifest/static scanner sees `format: uri` and can,
at best, *guess* that the tool might fetch it. mcpsnare **proved** it does: the tool really
fetches an arbitrary caller-supplied URL, with no allowlist, over an unauthenticated stdio
channel — reachable internal ranges and cloud-metadata endpoints included. That is textbook
SSRF (CWE-918).

Fair characterisation: `everything` is an *example* server, and fetching a URL is arguably its
intended demo behaviour, so this is not a "0-day in production". But it is a **confirmed,
unauthenticated SSRF primitive in the reference implementation** — exactly the shape that gets
copied into derivatives, and exactly the class a heuristic scanner cannot confirm and an active
one can.

## Part 3 — the passive lens on real manifests, and zero false positives

The most important result is one that produced *no* active finding. The **filesystem** server
is the hard test: it exposes `read_file`/`write_file` with path parameters and sandboxes them
to an allow-listed directory. mcpsnare fired its path-traversal payloads
(`../../../../etc/passwd`, `..\..\windows\win.ini`) against 13 of its 14 reachable tools — and
confirmed **nothing**. The sandbox held, and mcpsnare correctly did **not** false-positive on a
properly-contained server. Its passive lens still surfaced the declared surface honestly:
`write_file` as `fs-write` (HIGH), the three read tools as `fs-read` (MEDIUM), plus an INFO
`privileged_proxy` note that the manifest was reached with no credential presented (auth
boundary *unverified*, not "absent").

Across the whole corpus there were **zero false positives**, including on the servers reached
over a live backend (`memory`, 8/9 tools reachable; `sequential-thinking`, 1/1) where the
active checks genuinely ran and returned nothing.

## Results

| Server | Ran clean | Tools (reachable) | Confirmed active | Passive / notes |
| --- | --- | --- | --- | --- |
| `everything` | ✅ | 15 (3) | **1 SSRF (CONFIRMED)** | — |
| `memory` | ✅ | 9 (8) | 0 | 3× destructive (HIGH), privileged_proxy |
| `sequential-thinking` | ✅ | 1 (1) | 0 | — (genuinely clean) |
| `filesystem` | ✅ | 14 (13) | 0 (sandbox held) | fs-write HIGH, 3× fs-read MEDIUM, privileged_proxy |
| `github` | ✅ | 26 (3) | 0 | reachability note (no token → 23/26 tools errored) |
| `slack` | n/a¹ | — | — | won't start without creds → clean exit-2 |

¹ `slack` exits before the MCP handshake without its credentials; after Bug 2's fix mcpsnare
reports that cleanly instead of crashing.

**One confirmed true positive, zero false positives, two real bugs found and fixed.** The
`github` run is a good illustration of honest reporting under partial reachability: 26
high-privilege tools (`create_or_update_file`, `merge_pull_request`, …) were declared, but with
no token only 3 were reachable, so mcpsnare emitted its `reachability` note — *"active checks
inconclusive; an empty result here does not mean secure"* — rather than a clean bill of health.

## Honest caveats

- **Default mode.** Blocking time-based injection probes were not run (every report says how
  many injection points that skipped). A vulnerability reachable *only* via blind timing would
  not have been caught here; `--aggressive` adds those.
- **Partial reachability.** On several servers most tools weren't exercised (no credentials, or
  benign inputs the tool rejected). Absence of a finding on unexercised surface is untested, not
  verified-safe — which is precisely why the scan-metadata (`tools_reachable`, `time_based_skipped`)
  and the reachability note exist.
- **SSRF characterisation.** The `everything` finding is a confirmed capability in a reference
  *demo* server, not an incident in a production deployment.

## Reproduce it

```bash
pipx install mcpsnare
mcpsnare scan --stdio "npx -y @modelcontextprotocol/server-everything" --oob local
```

Everything above is one `mcpsnare scan` per server and the JSON it printed. The tool, the
fixtures, and the claim-to-test matrix are at <https://github.com/Den-Sec/mcpsnare>.
