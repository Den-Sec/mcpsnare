from mcpsnare.models import ToolInfo, InjectionPoint

_MAX_DEPTH = 4
_STRING_DEFAULT = "mcpsnare"
_CANARY_KEY = _STRING_DEFAULT   # synthesized key name for free-form/open-map injection points
_FORMAT_SAMPLES = {
    "uri": "https://mcpsnare.example/probe",
    "uri-reference": "https://mcpsnare.example/probe",
    "url": "https://mcpsnare.example/probe",
    "email": "probe@mcpsnare.example",
    "idn-email": "probe@mcpsnare.example",
    "date": "2026-01-01",
    "date-time": "2026-01-01T00:00:00Z",
    "time": "00:00:00",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "ipv4": "127.0.0.1",
    "ipv6": "::1",
    "hostname": "mcpsnare.example",
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


def _open_additional(schema):
    """Value-schema for extra keys when the object is an OPEN map, else None.
    ``additionalProperties`` as a subschema -> that schema; ``True`` -> free string;
    ``False``/absent -> None (not an explicitly open map)."""
    ap = schema.get("additionalProperties")
    if isinstance(ap, dict):
        return ap
    if ap is True:
        return {"type": "string"}
    return None


def _freeform_value(schema):
    """Value-schema for a synthesized canary key on a FREE-FORM object, or None for a fixed
    structured shape (Gap 4). An explicit open ``additionalProperties`` always wins. Otherwise
    an object that declares NO ``properties`` key at all is a free-form dict (JSON-Schema's
    ``additionalProperties`` defaults to true) - e.g. ``modify_element(parameters: dict)``,
    whose values a state-changing tool funnels into a sink but which today gets zero probes.
    A declared shape (``properties`` present, even ``{}`` for a no-arg tool) or an
    ``additionalProperties: false`` object is NOT free-form."""
    open_ap = _open_additional(schema)
    if open_ap is not None:
        return open_ap
    if "properties" in schema:                       # declared shape (incl. empty {}) -> not free-form
        return None
    if schema.get("additionalProperties") is False:  # explicitly closed
        return None
    return {"type": "string"}                        # typed/typeless object, no declared shape


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
    if t is None:  # typeless schema: infer container kind from shape (keep in sync with _walk)
        if "properties" in schema:
            t = "object"
        elif "items" in schema:
            t = "array"
        elif _open_additional(schema) is not None:  # typeless open map -> object (build {})
            t = "object"
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


def _walk(schema, path, root, depth, out, seen_refs):
    if depth > _MAX_DEPTH:
        return
    if isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen_refs:
            return
        seen_refs = seen_refs | {ref}
    schema = _branch(_resolve(schema, root), root)
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t is None:  # typeless schema: infer container kind from shape (keep in sync with _baseline)
        if "properties" in schema:
            t = "object"
        elif "items" in schema:
            t = "array"
        elif _open_additional(schema) is not None:  # typeless open map (only additionalProperties)
            t = "object"
    if t == "string":
        if not schema.get("enum") and "const" not in schema:
            out.append(path)
        return
    if t == "object":
        for name, sub in schema.get("properties", {}).items():
            child = f"{path}.{name}" if path else name
            _walk(sub, child, root, depth + 1, out, seen_refs)
        # Free-form container (additionalProperties / bare dict): probe a synthesized canary
        # key so state-changing tools carrying content in an open map are not left un-probed.
        free = _freeform_value(schema)
        if free is not None:
            key = f"{path}.{_CANARY_KEY}" if path else _CANARY_KEY
            _walk(free, key, root, depth + 1, out, seen_refs)
    elif t == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            _walk(items, f"{path}[0]", root, depth + 1, out, seen_refs)


def injection_points(tool: ToolInfo) -> list[InjectionPoint]:
    root = tool.input_schema or {}
    paths = []
    _walk(root, "", root, 0, paths, frozenset())
    base = build_baseline(root)
    return [InjectionPoint(tool=tool.name, json_path=p, base_args=base, param_name=p)
            for p in paths]
