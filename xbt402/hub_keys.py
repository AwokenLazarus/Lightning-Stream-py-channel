"""AGP-073 K1: the hub's ch2 payer keys sealed at rest (xbt-rs: crates/xbt402/src/hub_keys.rs).

The hub is the payer of every ch2 and holds each one's key in its state file (ch2.json). Each key is
sealed on its own with AES-256-GCM under the hub's wrap key, aad HUB_CH2_AAD, in the B2 keystore blob
format: {"v":1,"alg":"aes-256-gcm","kdf":"keyfile","salt":"","nonce","ct","aad"}, hex fields, the tag
at the end of ct. The rest of the record stays readable, and a key is sealed once and its blob reused
by every later save.

The wrap key is 32 bytes (raw, or 64 hex) in a file of its own: hub-wrap-key, 0600, refused when group
or others have any bit. A blob does not name its record: the book checks that each key it opens is the
record's payer_pub, so a blob moved to another record is refused.

Needs the `cryptography` package (requirements.txt), imported only when a hub opens its state.
"""
import os
import secrets
import stat

from .channel import ChannelError

HUB_CH2_AAD = "xbt402/hub-ch2"
WRAP_KEY_FILE = "hub-wrap-key"


def _err(msg: str) -> ChannelError:
    return ChannelError("keystore", msg)


def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key)


class WrapKey:
    """The key that seals the hub's ch2 keys. Never printed."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise _err("a wrap key is 32 bytes")
        self._key = bytes(key)

    def __repr__(self):
        return "WrapKey(..)"

    @classmethod
    def parse(cls, raw: bytes) -> "WrapKey":
        """32 raw bytes, or 64 hex characters (surrounding whitespace ignored)."""
        if len(raw) == 32:
            return cls(raw)
        try:
            k = bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            k = b""
        if len(k) != 32:
            raise _err("a wrap key is 32 bytes (raw or 64 hex characters)")
        return cls(k)

    @classmethod
    def load_or_create(cls, path: str) -> "WrapKey":
        """The wrap key in `path`, created (32 random bytes, 0600, never over an existing file) when it
        does not exist. Refused: not a regular file, or any bit for group or others."""
        if not os.path.exists(path):
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                fd = None                                   # another process made it first: read theirs
            if fd is not None:
                try:
                    os.write(fd, secrets.token_bytes(32))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                dfd = os.open(parent or ".", os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise _err(f"{path} is not a regular file")
        mode = st.st_mode & 0o777
        if os.name == "posix" and mode & 0o077:
            raise _err(f"{path} is mode {mode:o}: chmod 600 it")
        with open(path, "rb") as f:
            raw = f.read()
        try:
            return cls.parse(raw)
        except ChannelError:
            raise _err(f"{path}: a wrap key is 32 bytes (raw or 64 hex characters)")

    def seal(self, secret_hex: str) -> dict:
        """Seal one ch2 key (64 hex characters)."""
        try:
            pt = bytes.fromhex(secret_hex)
        except (TypeError, ValueError):
            pt = b""
        if len(pt) != 32:
            raise _err("a ch2 key is 64 hex characters")
        nonce = secrets.token_bytes(12)
        ct = _aesgcm(self._key).encrypt(nonce, pt, HUB_CH2_AAD.encode())
        return {"v": 1, "alg": "aes-256-gcm", "kdf": "keyfile", "salt": "", "nonce": nonce.hex(), "ct": ct.hex(),
                "aad": HUB_CH2_AAD}

    def open(self, blob: dict) -> str:
        """Open a sealed ch2 key: its 64 hex characters. Refused: another format, aad or kdf, a wrong
        wrap key, or a blob changed in any byte."""
        from cryptography.exceptions import InvalidTag
        if not isinstance(blob, dict) or blob.get("v") != 1 or blob.get("alg") != "aes-256-gcm" or blob.get("kdf") != "keyfile":
            raise _err("not a v1 aes-256-gcm keyfile blob")
        if blob.get("aad") != HUB_CH2_AAD:
            raise _err(f"sealed blob is for {blob.get('aad')!r}, not {HUB_CH2_AAD!r}")
        try:
            nonce, ct = bytes.fromhex(blob.get("nonce", "")), bytes.fromhex(blob.get("ct", ""))
        except (TypeError, ValueError):
            raise _err("nonce or ct is not hex")
        if len(nonce) != 12:
            raise _err("nonce")
        try:
            pt = _aesgcm(self._key).decrypt(nonce, ct, HUB_CH2_AAD.encode())
        except InvalidTag:
            raise _err("a sealed ch2 key does not open: another wrap key, or the state file was changed")
        if len(pt) != 32:
            raise _err("a sealed ch2 key is not 32 bytes")
        return pt.hex()
