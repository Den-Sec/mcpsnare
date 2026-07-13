from mcpsnare.models import ToolInfo
from mcpsnare.inject.mapper import build_baseline, injection_points

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
    assert base["host"] == "mcpsnare"
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
    assert build_baseline(schema) == {"config": {"path": "mcpsnare"}}


def test_baseline_resolves_ref():
    schema = {"$defs": {"Cfg": {"type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]}},
              "type": "object",
              "properties": {"config": {"$ref": "#/$defs/Cfg"}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcpsnare"}}


def test_baseline_array_of_strings():
    schema = {"type": "object",
              "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
              "required": ["paths"]}
    assert build_baseline(schema) == {"paths": ["mcpsnare"]}


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


def test_points_typeless_top_level_object():
    # properties present, no explicit type:"object" (hand-authored / zod-style schema)
    schema = {"properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}
    assert "cmd" in _paths(schema)


def test_points_typeless_nested_object():
    schema = {"type": "object",
              "properties": {"config": {"properties": {"path": {"type": "string"}},
                                        "required": ["path"]}},
              "required": ["config"]}
    assert "config.path" in _paths(schema)


def test_points_typeless_array():
    schema = {"type": "object",
              "properties": {"hosts": {"items": {"type": "string"}}},
              "required": ["hosts"]}
    assert "hosts[0]" in _paths(schema)


def test_baseline_typeless_nested_object():
    schema = {"type": "object",
              "properties": {"config": {"properties": {"path": {"type": "string"}},
                                        "required": ["path"]}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcpsnare"}}


# --- Gap 4: free-form container coverage (additionalProperties / bare dict / list[dict]) ---

def test_points_additional_properties_map_gets_canary_key():
    # modify_element(parameters: dict[str, str]) - the free-form dict the sink funnels into.
    schema = {"type": "object",
              "properties": {"parameters": {"type": "object",
                                            "additionalProperties": {"type": "string"}}},
              "required": ["parameters"]}
    assert "parameters.mcpsnare" in _paths(schema)


def test_points_additional_properties_true_gets_canary_key():
    schema = {"type": "object",
              "properties": {"opts": {"type": "object", "additionalProperties": True}},
              "required": ["opts"]}
    assert "opts.mcpsnare" in _paths(schema)


def test_points_bare_dict_no_properties_key_gets_canary_key():
    # A typed object with no declared 'properties' key at all is a free-form dict.
    schema = {"type": "object",
              "properties": {"meta": {"type": "object"}},
              "required": ["meta"]}
    assert "meta.mcpsnare" in _paths(schema)


def test_points_typeless_open_map_gets_canary_key():
    # No type, no properties, only additionalProperties -> still a free-form map.
    schema = {"type": "object",
              "properties": {"bag": {"additionalProperties": {"type": "string"}}},
              "required": ["bag"]}
    assert "bag.mcpsnare" in _paths(schema)


def test_points_list_of_free_form_dict_gets_canary_key():
    schema = {"type": "object",
              "properties": {"edits": {"type": "array",
                                       "items": {"type": "object",
                                                 "additionalProperties": {"type": "string"}}}},
              "required": ["edits"]}
    assert "edits[0].mcpsnare" in _paths(schema)


def test_points_structured_object_gets_no_canary_key():
    # Declared properties, no explicit open additionalProperties -> a fixed shape, no canary.
    schema = {"type": "object",
              "properties": {"cfg": {"type": "object",
                                     "properties": {"path": {"type": "string"}},
                                     "required": ["path"]}},
              "required": ["cfg"]}
    paths = _paths(schema)
    assert "cfg.path" in paths
    assert not any(p.endswith(".mcpsnare") for p in paths)


def test_points_empty_properties_no_arg_tool_gets_no_canary_key():
    # A no-arg tool declared as properties:{} must not sprout a spurious canary point.
    schema = {"type": "object", "properties": {}}
    assert _paths(schema) == set()


def test_points_additional_properties_false_gets_no_canary_key():
    schema = {"type": "object",
              "properties": {"cfg": {"type": "object",
                                     "properties": {"path": {"type": "string"}},
                                     "additionalProperties": False}},
              "required": ["cfg"]}
    assert not any(p.endswith(".mcpsnare") for p in _paths(schema))


def test_baseline_free_form_dict_is_empty_object():
    schema = {"type": "object",
              "properties": {"parameters": {"type": "object",
                                            "additionalProperties": {"type": "string"}}},
              "required": ["parameters"]}
    assert build_baseline(schema) == {"parameters": {}}


def test_baseline_typeless_open_map_is_empty_object():
    # _walk synthesizes an OBJECT canary point here (bag.mcpsnare); _baseline must build the
    # matching {} container, not fall through to the string default (baseline/probe type parity).
    schema = {"type": "object",
              "properties": {"bag": {"additionalProperties": {"type": "string"}}},
              "required": ["bag"]}
    assert build_baseline(schema) == {"bag": {}}
    assert "bag.mcpsnare" in _paths(schema)   # and the two stay in sync
