import base64
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mcprobe.oob.interactsh_client import InteractshClient


def test_interactsh_client_register_returns_domain(monkeypatch):
    posted = {}

    class _Resp:
        def raise_for_status(self): pass

    def fake_post(url, json=None, **k):
        posted["url"] = url
        posted["body"] = json
        return _Resp()

    monkeypatch.setattr("httpx.post", fake_post)
    c = InteractshClient(server="oast.example")
    domain = c.register()
    assert domain.endswith(".oast.example")
    assert posted["body"]["correlation-id"] in domain
    assert "public-key" in posted["body"] and "secret-key" in posted["body"]
    assert posted["url"].endswith("/register")


def test_interactsh_client_decrypts_poll(monkeypatch):
    # Simulate the SERVER side: encrypt a fake interaction the way interactsh does, and
    # assert the client decrypts it via its own RSA private key + the AES key.
    c = InteractshClient(server="oast.example")
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    interaction = {"protocol": "http", "full-id": "tok123abc", "raw-request": "GET /tok123abc"}
    # interactsh uses AES-256-CTR (verified against live oast.fun), not CFB.
    enc = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    ct = enc.update(json.dumps(interaction).encode()) + enc.finalize()
    data_item = base64.b64encode(iv + ct).decode()
    enc_key = c._key.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    poll_body = {"data": [data_item], "aes_key": base64.b64encode(enc_key).decode()}

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return poll_body

    monkeypatch.setattr("httpx.get", lambda *a, **k: _Resp())
    hits = c.poll()
    assert hits and hits[0]["full-id"] == "tok123abc"


def test_interactsh_client_poll_empty(monkeypatch):
    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"data": None, "aes_key": ""}

    monkeypatch.setattr("httpx.get", lambda *a, **k: _Resp())
    assert InteractshClient(server="oast.example").poll() == []
