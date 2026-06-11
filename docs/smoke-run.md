# Real-server smoke run

mcprobe is exercised in CI against bundled deliberately-vulnerable fixtures
(`tests/fixtures/`, see [claims-matrix.md](claims-matrix.md)). This document records a
manual smoke run against a **real, third-party MCP server** - the canonical
[`@modelcontextprotocol/server-everything`](https://www.npmjs.com/package/@modelcontextprotocol/server-everything)
reference server - to confirm mcprobe handles real-world schemas, enumerates real
tools/resources, and produces sane output without crashing or false-positing on a
benign target.

## What was scanned

`@modelcontextprotocol/server-everything` (run via `npx -y`) exposes, as seen by mcprobe:

- **13 tools** with **4 string injection points** (mcprobe's schema-aware mapper walked
  the real tool schemas, including nested/typed params).
- **2 resource templates** surfaced as injection surfaces by `ResourceToolView` (R-A6).

## Runs

All three completed cleanly (exit 0) with **zero false positives** (the reference
server is not vulnerable, so the correct result is no findings):

```
# default mode (non-blocking OOB/canary/pattern probes)
mcprobe scan --stdio "npx -y @modelcontextprotocol/server-everything" --oob none
-> 0 finding(s)   (exit 0)

# aggressive mode (adds blocking time-based cmd/SQL probes), JSON output
mcprobe scan --stdio "npx -y @modelcontextprotocol/server-everything" \
    --oob none --aggressive --output json
-> { ... "findings": [] }   (valid JSON, exit 0)
```

## Why this matters

The v1 review's core critique was that mcprobe "works on the toy fixture but is shallow
against real-world MCP servers." This run validates that the v1.1 hardening (schema-aware
injection, per-tool calibration, resource surface, concurrency) operates correctly against
a real server with real schemas - no crash, no spurious findings, and the resource-template
surface is exercised end to end.

> Note: a real **remote OOB** confirmation (interactsh) against an internet-reachable
> target is covered separately by [interactsh-runbook.md](interactsh-runbook.md); this
> smoke run used `--oob none` since the reference server is local and not vulnerable.
