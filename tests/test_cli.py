from mcprobe.cli import build_parser


def test_cli_parses_stdio_scan():
    args = build_parser().parse_args(["scan", "--stdio", "python server.py", "--output", "json"])
    assert args.cmd == "scan" and args.stdio == "python server.py" and args.output == "json"


def test_cli_parses_http_scan():
    args = build_parser().parse_args(["scan", "--http", "http://h/mcp", "--aggressive"])
    assert args.http == "http://h/mcp" and args.aggressive is True


def test_aggressive_note_present_in_default_mode():
    from mcprobe.cli import aggressive_note
    note = aggressive_note(False)
    assert note and "--aggressive" in note and "time-based" in note


def test_aggressive_note_absent_in_aggressive_mode():
    from mcprobe.cli import aggressive_note
    assert aggressive_note(True) is None
