import argparse
import asyncio
import os
import shlex

from mcprobe.report.render import to_json, to_sarif, to_markdown


def build_parser():
    p = argparse.ArgumentParser(prog="mcprobe")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an MCP server")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--stdio", help='command to launch the server, e.g. "python server.py"')
    g.add_argument("--http", help="streamable HTTP MCP endpoint URL")
    s.add_argument("--header", action="append", default=[], help="HTTP header k:v (repeatable)")
    s.add_argument("--oob", choices=["local", "interactsh", "none"], default="local")
    s.add_argument("--aggressive", action="store_true", help="reserved for v1.1 (no effect yet)")
    s.add_argument("--output", choices=["console", "json", "sarif", "md"], default="console")
    return p


async def _run(args):
    from mcprobe.connect.session import stdio_session, http_session
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
                findings = await scan_session(sess, oob=oob, transport="stdio")
        else:
            headers = dict(h.split(":", 1) for h in args.header)
            async with http_session(args.http, headers=headers) as sess:
                if headers:
                    async with http_session(args.http, headers={}) as sess_unauth:
                        findings = await scan_session(sess, oob=oob, transport="http",
                                                      call_tool_unauth=sess_unauth.call_tool)
                else:
                    findings = await scan_session(sess, oob=oob, transport="http")
    finally:
        if oob_cm:
            oob_cm.__exit__(None, None, None)
    renderers = {"json": to_json, "sarif": to_sarif, "md": to_markdown}
    if args.output in renderers:
        print(renderers[args.output](findings))
    else:
        print(f"\n{len(findings)} confirmed finding(s):")
        for f in findings:
            print(f"  [{f.severity.value.upper()}] {f.title}  ({f.confidence.value})")


def main():
    args = build_parser().parse_args()
    asyncio.run(_run(args))
