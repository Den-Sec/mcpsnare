from mcpsnare.cli import build_parser


def test_cli_parses_stdio_scan():
    args = build_parser().parse_args(["scan", "--stdio", "python server.py", "--output", "json"])
    assert args.cmd == "scan" and args.stdio == "python server.py" and args.output == "json"


def test_cli_parses_http_scan():
    args = build_parser().parse_args(["scan", "--http", "http://h/mcp", "--aggressive"])
    assert args.http == "http://h/mcp" and args.aggressive is True


def test_aggressive_note_present_in_default_mode():
    from mcpsnare.cli import aggressive_note
    note = aggressive_note(False)
    assert note and "--aggressive" in note and "time-based" in note


def test_aggressive_note_absent_in_aggressive_mode():
    from mcpsnare.cli import aggressive_note
    assert aggressive_note(True) is None


def test_cli_parses_scale_flags():
    args = build_parser().parse_args(
        ["scan", "--http", "http://h/mcp", "--concurrency", "8", "--rate", "10",
         "--oob-timeout", "30", "--oob-poll-interval", "1.5"])
    assert args.concurrency == 8 and args.rate == 10.0
    assert args.oob_timeout == 30.0 and args.oob_poll_interval == 1.5


def test_cli_rejects_nonpositive_rate():
    import pytest
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "--http", "http://h/mcp", "--rate", "0"])


def test_scan_header_summarizes_metadata():
    from mcpsnare.cli import scan_header
    from mcpsnare.models import ScanResult
    r = ScanResult(findings=[], target="python s.py", transport="stdio",
                   tools_discovered=3, tools_reachable=2, checks_executed=["cmd_injection"],
                   aggressive=True, time_based_skipped=0)
    h = scan_header(r)
    assert "python s.py" in h and "3 tool" in h and "2 reachable" in h and "cmd_injection" in h
