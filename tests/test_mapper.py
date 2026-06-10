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


def test_baseline_honors_enum():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]}},
              "required": ["mode"]}
    assert build_baseline(schema)["mode"] == "safe"


def test_baseline_honors_const():
    schema = {"type": "object",
              "properties": {"kind": {"const": "fixed"}},
              "required": ["kind"]}
    assert build_baseline(schema)["kind"] == "fixed"


def test_baseline_honors_format_uri():
    schema = {"type": "object",
              "properties": {"url": {"type": "string", "format": "uri"}},
              "required": ["url"]}
    assert build_baseline(schema)["url"].startswith("http")


def test_baseline_recurses_required_nested_object():
    schema = {"type": "object",
              "properties": {"config": {"type": "object",
                                        "properties": {"path": {"type": "string"}},
                                        "required": ["path"]}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcprobe"}}


def test_baseline_resolves_ref():
    schema = {"$defs": {"Cfg": {"type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]}},
              "type": "object",
              "properties": {"config": {"$ref": "#/$defs/Cfg"}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcprobe"}}


def test_baseline_array_of_strings():
    schema = {"type": "object",
              "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
              "required": ["paths"]}
    assert build_baseline(schema) == {"paths": ["mcprobe"]}


def _paths(schema):
    tool = ToolInfo(name="t", description="", input_schema=schema)
    return {p.json_path for p in injection_points(tool)}


def test_points_nested_object_path():
    schema = {"type": "object",
              "properties": {"params": {"type": "object",
                                        "properties": {"cmd": {"type": "string"}}}},
              "required": ["params"]}
    assert "params.cmd" in _paths(schema)


def test_points_array_item_path():
    schema = {"type": "object",
              "properties": {"hosts": {"type": "array", "items": {"type": "string"}}},
              "required": ["hosts"]}
    assert "hosts[0]" in _paths(schema)


def test_points_resolve_ref():
    schema = {"$defs": {"Cfg": {"type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]}},
              "type": "object",
              "properties": {"config": {"$ref": "#/$defs/Cfg"}},
              "required": ["config"]}
    assert "config.path" in _paths(schema)


def test_points_skip_enum_string():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]},
                             "path": {"type": "string"}},
              "required": ["mode", "path"]}
    paths = _paths(schema)
    assert "path" in paths and "mode" not in paths


def test_points_baseline_is_schema_valid():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]},
                             "path": {"type": "string"}},
              "required": ["mode", "path"]}
    tool = ToolInfo(name="t", description="", input_schema=schema)
    pt = next(p for p in injection_points(tool) if p.json_path == "path")
    assert pt.base_args["mode"] == "safe"  # enum gate satisfied


def test_points_self_referential_ref_terminates():
    schema = {"$defs": {"Node": {"type": "object",
                                 "properties": {"name": {"type": "string"},
                                                "child": {"$ref": "#/$defs/Node"}}}},
              "type": "object",
              "properties": {"root": {"$ref": "#/$defs/Node"}},
              "required": ["root"]}
    tool = ToolInfo(name="t", description="", input_schema=schema)
    points = injection_points(tool)  # must not hang (depth cap + visited refs)
    assert "root.name" in {p.json_path for p in points}
