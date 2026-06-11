# Real out-of-band (OOB) confirmation with interactsh

For a target that cannot reach your localhost (e.g. a remote HTTP MCP server),
mcprobe confirms blind command-injection / SSRF via an interactsh / OAST server.

## Out of the box

mcprobe ships a real interactsh client (`mcprobe.oob.interactsh_client.InteractshClient`)
implementing the interactsh **RSA-OAEP(SHA-256) + AES-256-CTR** protocol. Just select it:

    mcprobe scan --http https://target/mcp --oob interactsh

It registers with the public `oast.fun` server by default. Point it elsewhere (or at a
self-hosted interactsh server) with `--interactsh-server`:

    mcprobe scan --http https://target/mcp --oob interactsh --interactsh-server my.oast.server

A vulnerable target that executes an injected `curl http://<token>.<oast-domain>` makes a
DNS/HTTP callback that interactsh records; mcprobe's poll-until-hit loop catches it and
reports a **CONFIRMED** finding naming the firing payload.

## Bring your own client (optional)

`InteractshOOB` accepts any object exposing `register() -> domain` and
`poll() -> list[dict]`, so you can wrap a different OAST/interactsh client:

    from mcprobe.oob.interactsh import InteractshOOB
    oob = InteractshOOB(MyClient())   # used via the SDK

## Verification status

- The client's crypto (RSA decrypt of the AES key, AES-CTR decrypt of interactions) is
  **unit-tested in CI** with a server-side round-trip (`tests/test_interactsh_client.py`).
- The full path has been **manually verified live against the public `oast.fun`**: a real
  DNS callback to a mcprobe-generated subdomain was registered, polled, decrypted, and
  matched to its token end to end. This live round-trip is not run in CI (network /
  non-determinism), but the protocol (AES-CTR, case-insensitive host matching) was
  corrected to match the real server during that verification.
