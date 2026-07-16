import argparse
import asyncio
import os
import shlex
import sys

from mcp.shared.exceptions import McpError

from mcpsnare.report.render import to_json, to_sarif, to_markdown

# Target-side / connection failures (server won't start, exits before the handshake, endpoint
# unreachable, protocol error). These get a clean message; anything else (a mcpsnare logic bug:
# AttributeError/KeyError/...) is deliberately NOT caught here, so its traceback stays visible.
_CONNECT_ERRORS = (ConnectionError, OSError, EOFError, McpError)


def _connect_error_leaf(exc):
    """Unwrap anyio task-group ExceptionGroups down to the underlying failure."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def _positive_float(s):
    v = float(s)
    if v <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return v


def aggressive_note(aggressive: bool) -> str | None:
    """Honest note for default (non-aggressive) scans: blocking time-based probes
    were skipped, so an empty report must not be read as 'secure'. None when
    aggressive (nothing was skipped)."""
    if aggressive:
        return None
    return ("[i] Default mode: blocking time-based probes were skipped. "
            "Re-run with --aggressive to add time-based command-injection and SQL-injection detection.")


def scan_header(result) -> str:
    """One-line console summary of the scan's metadata (target, coverage, checks), so a
    console report says what was actually tested, not only what was found."""
    return (f"[i] Target {result.target or '(n/a)'} ({result.transport}): "
            f"{result.tools_discovered} tool(s), {result.tools_reachable} reachable; "
            f"checks: {', '.join(result.checks_executed)}; aggressive={result.aggressive}")


def build_parser():
    p = argparse.ArgumentParser(prog="mcpsnare")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an MCP server")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--stdio", help='command to launch the server, e.g. "python server.py"')
    g.add_argument("--http", help="streamable HTTP MCP endpoint URL")
    s.add_argument("--header", action="append", default=[], help="HTTP header k:v (repeatable)")
    s.add_argument("--oob", choices=["local", "interactsh", "none"], default="local")
    s.add_argument("--interactsh-server", default="oast.fun",
                   help="interactsh/OAST server domain for --oob interactsh (default oast.fun)")
    s.add_argument("--aggressive", action="store_true",
                   help="also send blocking time-based (sleep) probes; default sends only non-blocking OOB/canary/pattern probes")
    s.add_argument("--concurrency", type=int, default=4,
                   help="max concurrent probe requests (default 4)")
    s.add_argument("--rate", type=_positive_float, default=None,
                   help="max requests/second (default unlimited)")
    s.add_argument("--oob-timeout", type=float, default=20.0,
                   help="seconds to poll for OOB callbacks (default 20)")
    s.add_argument("--oob-poll-interval", type=float, default=2.5,
                   help="OOB poll interval seconds (default 2.5)")
    s.add_argument("--output", choices=["console", "json", "sarif", "md"], default="console")
    return p


async def _run(args):
    from mcpsnare.connect.session import stdio_session, http_session
    from mcpsnare.connect.resources import ResourceToolView
    from mcpsnare.engine import scan_session
    import mcpsnare.checks  # register
    from mcpsnare.oob.local import LocalOOB

    print("[!] mcpsnare - authorized testing only.")
    oob_cm = None
    oob = None
    if args.oob == "local":
        oob_cm = LocalOOB()
        oob = oob_cm.__enter__()
    elif args.oob == "interactsh":
        from mcpsnare.oob.interactsh import InteractshOOB
        from mcpsnare.oob.interactsh_client import InteractshClient
        oob = InteractshOOB(InteractshClient(server=args.interactsh_server))
    try:
        if args.stdio:
            argv = shlex.split(args.stdio, posix=(os.name != "nt"))
            async with stdio_session(argv) as sess:
                findings = await scan_session(sess, oob=oob, transport="stdio", aggressive=args.aggressive,
                                              concurrency=args.concurrency, rate=args.rate,
                                              oob_timeout=args.oob_timeout,
                                              oob_poll_interval=args.oob_poll_interval, target=args.stdio)
                findings += await scan_session(ResourceToolView(sess), oob=oob, transport="stdio",
                                               aggressive=args.aggressive, concurrency=args.concurrency,
                                               rate=args.rate, check_ids=["path_traversal", "info_leak"],
                                               target=args.stdio)
        else:
            headers = dict(h.split(":", 1) for h in args.header)
            async with http_session(args.http, headers=headers) as sess:
                if headers:
                    async with http_session(args.http, headers={}) as sess_unauth:
                        findings = await scan_session(sess, oob=oob, transport="http",
                                                      call_tool_unauth=sess_unauth.call_tool, aggressive=args.aggressive,
                                                      concurrency=args.concurrency, rate=args.rate,
                                                      oob_timeout=args.oob_timeout,
                                                      oob_poll_interval=args.oob_poll_interval, target=args.http)
                        findings += await scan_session(ResourceToolView(sess), oob=oob, transport="http",
                                                       aggressive=args.aggressive, concurrency=args.concurrency,
                                                       rate=args.rate, check_ids=["path_traversal", "info_leak"],
                                                       target=args.http)
                else:
                    findings = await scan_session(sess, oob=oob, transport="http", aggressive=args.aggressive,
                                                  concurrency=args.concurrency, rate=args.rate,
                                                  oob_timeout=args.oob_timeout,
                                                  oob_poll_interval=args.oob_poll_interval, target=args.http)
                    findings += await scan_session(ResourceToolView(sess), oob=oob, transport="http",
                                                   aggressive=args.aggressive, concurrency=args.concurrency,
                                                   rate=args.rate, check_ids=["path_traversal", "info_leak"],
                                                   target=args.http)
    except Exception as e:
        leaf = _connect_error_leaf(e)
        if isinstance(leaf, _CONNECT_ERRORS):
            print(f"[!] Could not connect to the target ({type(leaf).__name__}: {leaf}). "
                  "Check the --stdio command / --http URL and any environment the server needs "
                  "(some servers exit without their credentials).", file=sys.stderr)
            raise SystemExit(2)
        raise  # unexpected internal error: let the traceback surface it
    finally:
        if oob_cm:
            oob_cm.__exit__(None, None, None)
    renderers = {"json": to_json, "sarif": to_sarif, "md": to_markdown}
    if args.output in renderers:
        print(renderers[args.output](findings))
    else:
        print(scan_header(findings))
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print(f"  [{f.severity.value.upper()}] {f.title}  ({f.confidence.value})")
    note = aggressive_note(args.aggressive)
    if note:
        print(note, file=sys.stderr)


def main():
    args = build_parser().parse_args()
    asyncio.run(_run(args))
