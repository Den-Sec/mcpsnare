import base64
import json
import secrets

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand(n):
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


class InteractshClient:
    """Minimal real interactsh client: ``register() -> domain``, ``poll() -> list[dict]``.

    Implements the interactsh RSA-OAEP(SHA-256) + AES-256-CFB protocol so mcprobe's
    ``InteractshOOB`` works against a public OAST (default ``oast.fun``) or a self-hosted
    server out of the box. Inject via: ``InteractshOOB(InteractshClient())``.
    """

    def __init__(self, server="oast.fun", token=None, timeout=10.0):
        self.server = server.rstrip("/")
        self._base = f"https://{self.server}"
        self._token = token
        self._timeout = timeout
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._correlation_id = _rand(20)
        self._secret = _rand(36)
        self._domain = f"{self._correlation_id}{_rand(13)}.{self.server}"

    def _pubkey_b64(self):
        pem = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(pem).decode()

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = self._token
        return h

    def register(self):
        body = {
            "public-key": self._pubkey_b64(),
            "secret-key": self._secret,
            "correlation-id": self._correlation_id,
        }
        httpx.post(f"{self._base}/register", json=body, headers=self._headers(),
                   timeout=self._timeout).raise_for_status()
        return self._domain

    def poll(self):
        resp = httpx.get(f"{self._base}/poll",
                         params={"id": self._correlation_id, "secret": self._secret},
                         headers=self._headers(), timeout=self._timeout)
        resp.raise_for_status()
        body = resp.json()
        data = body.get("data") or []
        if not data:
            return []
        aes_key = self._key.decrypt(
            base64.b64decode(body["aes_key"]),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
        out = []
        for item in data:
            raw = base64.b64decode(item)
            iv, ct = raw[:16], raw[16:]
            # interactsh encrypts interactions with AES-256-CTR (IV = the 16-byte
            # counter block), NOT CFB - verified against a live oast.fun round-trip.
            dec = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
            plain = dec.update(ct) + dec.finalize()
            try:
                out.append(json.loads(plain.decode("utf-8", "ignore")))
            except json.JSONDecodeError:
                out.append({"raw": plain.decode("utf-8", "ignore")})
        return out
