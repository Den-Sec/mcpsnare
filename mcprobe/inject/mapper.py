from mcprobe.models import ToolInfo, InjectionPoint

_MAX_DEPTH = 4
_STRING_DEFAULT = "mcprobe"
_FORMAT_SAMPLES = {
    "uri": "https://mcprobe.example/probe",
    "uri-reference": "https://mcprobe.example/probe",
    "url": "https://mcprobe.example/probe",
    "email": "probe@mcprobe.example",
    "idn-email": "probe@mcprobe.example",
    "date": "2026-01-01",
    "date-time": "2026-01-01T00:00:00Z",
    "time": "00:00:00",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "ipv4": "127.0.0.1",
    "ipv6": "::1",
    "hostname": "mcprobe.example",
}


def _deref(ref, root):
    if not ref.startswith("#/"):
        return {}
    node = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _resolve(schema, root):
    seen = set()
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return {}
        seen.add(ref)
        schema = _deref(ref, root)
    return schema if isinstance(schema, dict) else {}


def _branch(schema, root):
    """Collapse anyOf/oneOf to a single viable (non-null) branch, best-effort."""
    for key in ("anyOf", "oneOf"):
        for opt in schema.get(key, []):
            resolved = _resolve(opt, root)
            if resolved.get("type") != "null":
                return resolved
    return schema


def _string_value(schema):
    fmt = schema.get("format")
    if fmt in _FORMAT_SAMPLES:
        return _FORMAT_SAMPLES[fmt]
    val = _STRING_DEFAULT
    minlen = schema.get("minLength")
    if isinstance(minlen, int) and len(val) < minlen:
        val += "x" * (minlen - len(val))
    return val


def _baseline(schema, root, depth):
    schema = _branch(_resolve(schema, root), root)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t == "string":
        return _string_value(schema)
    if t == "integer":
        return int(schema.get("minimum", 1)) or 1
    if t == "number":
        return schema.get("minimum", 1) or 1
    if t == "boolean":
        return True
    if t == "array":
        if depth >= _MAX_DEPTH:
            return []
        items = _resolve(schema.get("items", {}), root)
        n = max(int(schema.get("minItems", 1)), 1)
        return [_baseline(items, root, depth + 1) for _ in range(n)] if items else []
    if t == "object":
        if depth >= _MAX_DEPTH:
            return {}
        props = schema.get("properties", {})
        required = schema.get("required", list(props))
        return {name: _baseline(props[name], root, depth + 1)
                for name in required if name in props}
    return _STRING_DEFAULT


def build_baseline(schema: dict) -> dict:
    root = schema or {}
    resolved = _resolve(root, root)
    props = resolved.get("properties", {})
    required = resolved.get("required", list(props))
    return {name: _baseline(props[name], root, 1)
            for name in required if name in props}


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
