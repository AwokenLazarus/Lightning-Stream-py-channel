"""secp256k1 ECDSA via libsecp256k1 (`coincurve`), same four functions as v1.

Point helpers (`_add`, `_mul`, `_decode_pub`) and the curve constants stay on the
pure-Python oracle — they are not the per-call hot path. `sign` / `verify` / `pubkey`
use coincurve when installed (the wave-2 target: p50 ≤ 2 ms per paid call). If
coincurve is missing we fall back to the oracle so unit tests still run.

The oracle module (`ecc_oracle`) is kept imported so tests can compare the two.
"""
from . import ecc_oracle as _oracle

N = _oracle.N
P = _oracle.P
G = _oracle.G
_add = _oracle._add
_mul = _oracle._mul
_decode_pub = _oracle._decode_pub

try:
    from coincurve import PrivateKey, PublicKey
    BACKEND = "coincurve"
except ImportError:  # pragma: no cover - CI without the extra
    BACKEND = "oracle"


def pubkey(secret: int) -> bytes:
    """Compressed SEC1 public key."""
    if BACKEND == "coincurve":
        return PrivateKey(secret.to_bytes(32, "big")).public_key.format(compressed=True)
    return _oracle.pubkey(secret)


def sign(secret: int, msg32: bytes) -> bytes:
    """DER signature (low-S) over a 32-byte digest, without the hash-type byte."""
    if BACKEND == "coincurve":
        return PrivateKey(secret.to_bytes(32, "big")).sign(msg32, hasher=None)
    return _oracle.sign(secret, msg32)


def verify(pub: bytes, msg32: bytes, der: bytes) -> bool:
    """Verify a DER signature; rejects high-S like the node's standardness rules."""
    if BACKEND == "coincurve":
        try:
            return bool(PublicKey(pub).verify(der, msg32, hasher=None))
        except Exception:
            return False
    return _oracle.verify(pub, msg32, der)
