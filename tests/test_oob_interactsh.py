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
