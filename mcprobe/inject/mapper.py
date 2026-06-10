from mcprobe.models import ToolInfo, InjectionPoint

_DEFAULTS = {"string": "mcprobe", "integer": 1, "number": 1, "boolean": True,
             "array": [], "object": {}}


def build_baseline(schema: dict) -> dict:
    props = schema.get("properties", {})
    required = schema.get("required", list(props))
    out = {}
    for name in required:
        t = props.get(name, {}).get("type", "string")
        out[name] = _DEFAULTS.get(t, "mcprobe")
    return out


def injection_points(tool: ToolInfo) -> list[InjectionPoint]:
    props = tool.input_schema.get("properties", {})
    base = build_baseline(tool.input_schema)
    points = []
    for name, spec in props.items():
        if spec.get("type") == "string":
            args = dict(base)
            args.setdefault(name, "mcprobe")
            points.append(InjectionPoint(tool=tool.name, json_path=name,
                                         base_args=args, param_name=name))
    return points
