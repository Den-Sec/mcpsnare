from mcprobe.cli import build_parser


def test_cli_parses_stdio_scan():
    args = build_parser().parse_args(["scan", "--stdio", "python server.py", "--output", "json"])
    assert args.cmd == "scan" and args.stdio == "python server.py" and args.output == "json"


def test_cli_parses_http_scan():
    args = build_parser().parse_args(["scan", "--http", "http://h/mcp", "--aggressive"])
    assert args.http == "http://h/mcp" and args.aggressive is True
