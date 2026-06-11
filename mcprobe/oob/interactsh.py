import uuid


class InteractshOOB:
    """Thin wrapper. `client` must expose register() -> domain and poll() -> list[dict].
    Inject a real interactsh client in production; tests pass a fake."""

    def __init__(self, client):
        self._client = client
        self._domain = client.register()
        self._cache: list[dict] = []
        self._tokens: list[str] = []

    def new_token(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:12]
        self._tokens.append(token)
        return token, f"http://{token}.{self._domain}"

    def interactions(self, token: str) -> list[dict]:
        # Case-insensitive: interactsh randomises the case of the recorded host
        # (DNS 0x20 encoding), so a lowercase token must still match.
        self._cache.extend(self._client.poll() or [])
        tl = token.lower()
        return [i for i in self._cache if tl in str(i).lower()]

    def poll_all(self) -> dict[str, list[dict]]:
        self._cache.extend(self._client.poll() or [])
        out: dict[str, list[dict]] = {}
        for tok in self._tokens:
            tl = tok.lower()
            hits = [i for i in self._cache if tl in str(i).lower()]
            if hits:
                out[tok] = hits
        return out
