import argparse
import asyncio
import os
import shlex
import sys

from mcprobe.report.render import to_json, to_sarif, to_markdown


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


def build_parser():
    p = argparse.ArgumentParser(prog="mcprobe")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an MCP server")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--stdio", help='command to launch the server, e.g. "python server.py"')
    g.add_argument("--http", help="streamable HTTP MCP endpoint URL")
    s.add_argument("--header", action="append", default=[], help="HTTP header k:v (repeatable)")
    s.add_argument("--oob", choices=["local", "interactsh", "none"], default="local")
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
    from mcprobe.connect.session import stdio_session, http_session
    from mcprobe.connect.resources import ResourceToolView
    from mcprobe.engine import scan_session
    import mcprobe.checks  # register
    from mcprobe.oob.local import LocalOOB

    print("[!] mcprobe - authorized testing only.")
    oob_cm = None
    oob = None
    if args.oob == "local":
        oob_cm = LocalOOB()
        oob = oob_cm.__enter__()
    elif args.oob == "interactsh":
        try:
            from mcprobe.oob.interactsh import InteractshOOB
            from interactsh_client import InteractshClient  # injectable client
        except ImportError:
            raise SystemExit("interactsh selected but no interactsh client is installed. "
                             "Install a client exposing register()->domain and poll()->list, "
                             "or use --oob local.")
        oob = InteractshOOB(InteractshClient())
    try:
        if args.stdio:
            argv = shlex.split(args.stdio, posix=(os.name != "nt"))
            async with stdio_session(argv) as sess:
                findings = await scan_session(sess, oob=oob, transport="stdio", aggressive=args.aggressive,
                                              concurrency=args.concurrency, rate=args.rate,
                                              oob_timeout=args.oob_timeout,
                                              oob_poll_interval=args.oob_poll_interval)
                findings += await scan_session(ResourceToolView(sess), oob=oob, transport="stdio",
                                               aggressive=args.aggressive, concurrency=args.concurrency,
                                               rate=args.rate, check_ids=["path_traversal", "info_leak"])
        else:
            headers = dict(h.split(":", 1) for h in args.header)
            async with http_session(args.http, headers=headers) as sess:
                if headers:
                    async with http_session(args.http, headers={}) as sess_unauth:
                        findings = await scan_session(sess, oob=oob, transport="http",
                                                      call_tool_unauth=sess_unauth.call_tool, aggressive=args.aggressive,
                                                      concurrency=args.concurrency, rate=args.rate,
                                                      oob_timeout=args.oob_timeout,
                                                      oob_poll_interval=args.oob_poll_interval)
                        findings += await scan_session(ResourceToolView(sess), oob=oob, transport="http",
                                                       aggressive=args.aggressive, concurrency=args.concurrency,
                                                       rate=args.rate, check_ids=["path_traversal", "info_leak"])
                else:
                    findings = await scan_session(sess, oob=oob, transport="http", aggressive=args.aggressive,
                                                  concurrency=args.concurrency, rate=args.rate,
                                                  oob_timeout=args.oob_timeout,
                                                  oob_poll_interval=args.oob_poll_interval)
                    findings += await scan_session(ResourceToolView(sess), oob=oob, transport="http",
                                                   aggressive=args.aggressive, concurrency=args.concurrency,
                                                   rate=args.rate, check_ids=["path_traversal", "info_leak"])
    finally:
        if oob_cm:
            oob_cm.__exit__(None, None, None)
    renderers = {"json": to_json, "sarif": to_sarif, "md": to_markdown}
    if args.output in renderers:
        print(renderers[args.output](findings))
    else:
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print(f"  [{f.severity.value.upper()}] {f.title}  ({f.confidence.value})")
    note = aggressive_note(args.aggressive)
    if note:
        print(note, file=sys.stderr)


def main():
    args = build_parser().parse_args()
    asyncio.run(_run(args))
