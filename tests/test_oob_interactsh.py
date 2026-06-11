from mcprobe.oob.interactsh import InteractshOOB


class FakeClient:
    def __init__(self):
        self.polled = False

    def register(self):
        return "abc.oast.fun"

    def poll(self):
        self.polled = True
        return [{"unique-id": "tok", "raw": "GET /tok"}]


def test_interactsh_token_and_poll():
    oob = InteractshOOB(client=FakeClient())
    token, url = oob.new_token()
    assert url.endswith(".oast.fun")
    hits = oob.interactions(token)
    assert isinstance(hits, list)


class _CaseClient:
    """interactsh randomises the case of the recorded host (DNS 0x20 encoding)."""
    def register(self):
        return "abc.oast.example"
    def poll(self):
        return [{"protocol": "dns", "full-id": "DEADbeefCAFE0.abc.oast.example"}]


def test_interactsh_oob_matches_token_case_insensitively():
    # A lowercase token must still match a mixed-case recorded host (verified live:
    # interactsh varies host case, so case-sensitive matching missed real callbacks).
    oob = InteractshOOB(client=_CaseClient())
    assert oob.interactions("deadbeefcafe0")
    oob._tokens.append("deadbeefcafe0")
    assert "deadbeefcafe0" in oob.poll_all()
