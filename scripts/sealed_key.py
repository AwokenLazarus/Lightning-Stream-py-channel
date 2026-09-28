"""The provider's payTo secret, sealed at rest (AGP-017 P7).

A demo provider draws a fresh payTo secret on every start. That is fine on regtest and fatal on
mainnet: a channel's payee output P = payTo + t can only be spent with that start's secret, so a
restart after a close would strand the provider's money. Here the secret is created once, sealed
with AES-256-GCM and never rewritten:

  payto.key    {"v": 1, "pub": <payTo pubkey hex>, "sealed": {...}}  0600, created with O_EXCL
  wrapping key a 32-byte key file (raw or hex, 0600, created once), or a passphrase in
               XBT402_PAYTO_PASSPHRASE (scrypt N=2^15, r=8, p=1), removed from the environment once read

Back up both files (the runbook puts them in a password manager). Losing either after a close loses the
payee output. Needs the `cryptography` package (scripts/requirements-provider.txt).
"""
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ENV_PASSPHRASE = "XBT402_PAYTO_PASSPHRASE"
AAD = "xbt402/payto-secret"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class SealedKeyError(RuntimeError):
    pass


class Wrap:
    """The wrapping key: a 32-byte key or a passphrase (scrypt with the blob's salt)."""

    def __init__(self, key: bytes = None, passphrase: bytes = None):
        if (key is None) == (passphrase is None):
            raise ValueError("exactly one of key / passphrase")
        if key is not None and len(key) != 32:
            raise ValueError("wrapping key must be 32 bytes")
        self.key, self.passphrase = key, passphrase
        self.kind = "keyfile" if key is not None else "scrypt"

    def derive(self, salt: bytes) -> bytes:
        if self.key is not None:
            return self.key
        return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(self.passphrase)

    @classmethod
    def from_config(cls, wrap_path: str = "", env=os.environ) -> "Wrap":
        pw = env.pop(ENV_PASSPHRASE, None) if hasattr(env, "pop") else None
        if pw and wrap_path:
            raise SealedKeyError(f"set only one of the wrap key file / {ENV_PASSPHRASE}")
        if pw:
            return cls(passphrase=pw.encode())
        if not wrap_path:
            raise SealedKeyError(f"no wrapping key: set payto_wrap in the config or {ENV_PASSPHRASE}")
        return cls(key=load_or_create_wrap(wrap_path))


def _write_new(path: str, data: bytes) -> None:
    """Create `path` 0600 with O_EXCL: an existing key file is never overwritten."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def load_or_create_wrap(path: str) -> bytes:
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        _write_new(path, secrets.token_bytes(32))
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) == 32:
        return raw
    try:
        key = bytes.fromhex(raw.strip().decode())
    except (UnicodeDecodeError, ValueError):
        key = b""
    if len(key) != 32:
        raise SealedKeyError(f"{path} must hold 32 bytes (raw or 64 hex characters)")
    return key


def seal(secret: int, wrap: Wrap) -> dict:
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(wrap.derive(salt)).encrypt(nonce, secret.to_bytes(32, "big"), AAD.encode())
    return {"v": 1, "alg": "aes-256-gcm", "kdf": wrap.kind, "salt": salt.hex(), "nonce": nonce.hex(),
            "ct": ct.hex(), "aad": AAD}


def unseal(blob: dict, wrap: Wrap) -> int:
    if blob.get("v") != 1 or blob.get("alg") != "aes-256-gcm" or blob.get("aad") != AAD:
        raise SealedKeyError("unknown sealed payTo format")
    if blob.get("kdf") != wrap.kind:
        raise SealedKeyError(f"payTo sealed with {blob.get('kdf')}, but the wrapping key is a {wrap.kind}")
    try:
        raw = AESGCM(wrap.derive(bytes.fromhex(blob["salt"]))).decrypt(
            bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), AAD.encode())
    except Exception as e:  # noqa: BLE001 - InvalidTag: wrong key or a tampered file
        raise SealedKeyError("cannot open the payTo key: wrong wrapping key or tampered file") from e
    return int.from_bytes(raw, "big")


def load_or_create_payto(path: str, wrap: Wrap, pubkey) -> tuple:
    """(secret, created). `pubkey(secret) -> bytes`. A file whose sealed secret does not match its
    recorded pub is refused, never replaced."""
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        secret = secrets.randbelow(N - 1) + 1
        doc = {"v": 1, "pub": pubkey(secret).hex(), "sealed": seal(secret, wrap)}
        _write_new(path, json.dumps(doc, indent=1).encode())
        return secret, True
    if os.stat(path).st_mode & 0o077:
        raise SealedKeyError(f"{path} is readable by group or others: chmod 600 it")
    with open(path) as f:
        doc = json.load(f)
    secret = unseal(doc.get("sealed") or {}, wrap)
    if not 0 < secret < N or pubkey(secret).hex() != doc.get("pub"):
        raise SealedKeyError(f"{path}: the sealed secret does not match its recorded pub")
    return secret, False
