from mcprobe.models import ToolInfo
from mcprobe.inject.mapper import build_baseline, injection_points

SCHEMA = {
    "type": "object",
    "properties": {
        "host": {"type": "string"},
        "count": {"type": "integer"},
        "verbose": {"type": "boolean"},
    },
    "required": ["host", "count"],
}


def test_build_baseline_fills_required_by_type():
    base = build_baseline(SCHEMA)
    assert base["host"] == "mcprobe"
    assert base["count"] == 1
    assert "verbose" not in base


def test_injection_points_only_strings():
    tool = ToolInfo(name="ping", description="", input_schema=SCHEMA)
    pts = injection_points(tool)
    names = {p.param_name for p in pts}
    assert names == {"host"}
    assert pts[0].base_args["count"] == 1
