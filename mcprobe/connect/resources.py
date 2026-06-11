import re

from mcprobe.models import ToolInfo

_TMPL_PARAM = re.compile(r"\{([^}/]+)\}")


class ResourceToolView:
    """Presents an object's resource templates as tool-like objects so the existing
    engine (injection_points + checks + oracles) can scan resources. A templated
    ``{param}`` in a URI template becomes a string injection point; ``call_tool`` fills
    the template and ``read_resource``s it.

    The wrapped object must expose ``list_resource_templates() -> list[(name, uriTemplate)]``
    and ``read_resource(uri) -> str`` (mcprobe's Session does).
    """

    def __init__(self, session):
        self._session = session
        self._templates = {}  # tool_name -> uriTemplate

    async def list_tools(self):
        tools = []
        for name, tmpl in await self._session.list_resource_templates():
            params = _TMPL_PARAM.findall(tmpl)
            if not params:
                continue
            props = {p: {"type": "string"} for p in params}
            schema = {"type": "object", "properties": props, "required": params}
            tool_name = f"resource:{tmpl}"
            self._templates[tool_name] = tmpl
            tools.append(ToolInfo(name=tool_name, description=name, input_schema=schema))
        return tools

    async def call_tool(self, name, args):
        tmpl = self._templates[name]
        uri = tmpl
        for key, value in args.items():
            uri = uri.replace("{" + key + "}", str(value))
        return await self._session.read_resource(uri)
