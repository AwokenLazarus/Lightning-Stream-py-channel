"""secp256k1 ECDSA via libsecp256k1 (`coincurve`), same four functions as v1, plus `ecdh`.

Point helpers (`_add`, `_mul`, `_decode_pub`) and the curve constants stay on the
pure-Python oracle — they only ever see public data (the payTo tweak, verification). `sign` /
`verify` / `pubkey` / `ecdh` use coincurve when installed (the wave-2 target: p50 ≤ 2 ms per paid
call). If coincurve is missing they fall back to pure Python, hardened for secret scalars: a
fixed-length Montgomery ladder and a blinded nonce inversion (XBT-061 H4). That closes the remote
nonce-length leak on receipt signing, but pure Python is still not constant time: keys holding
real value need coincurve.

Every signature is checked for BIP66 strict DER before it is verified, whichever backend runs
(XBT-061 C1): segwit v0 consensus refuses any other encoding, so a state that only parses
loosely is one the payee can never close with.

The oracle module (`ecc_oracle`) is kept imported so tests can compare the two.
"""
import secrets

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


def is_strict_der(der: bytes) -> bool:
    """BIP66 strict DER (Bitcoin Core IsValidSignatureEncoding), for a signature WITHOUT its
    hash-type byte."""
    n = len(der)
    if n < 8 or n > 72 or der[0] != 0x30 or der[1] != n - 2 or der[2] != 0x02:
        return False
    lr = der[3]
    if lr == 0 or 5 + lr >= n or der[4] & 0x80 or (lr > 1 and der[4] == 0 and not der[5] & 0x80):
        return False
    if der[4 + lr] != 0x02:
        return False
    ls = der[5 + lr]
    if ls == 0 or 6 + lr + ls != n or der[6 + lr] & 0x80 or (ls > 1 and der[6 + lr] == 0 and not der[7 + lr] & 0x80):
        return False
    return True


def _mul_secret(k: int, pt=G):
    """k * pt for a SECRET scalar with a fixed sequence of operations. k is lifted to the 257-bit
    k + N or k + 2N (the same point; OpenSSL's fix for Minerva-class nonce-length leaks) and run
    through a Montgomery ladder that does one add and one double per bit, whatever the bit.
    Calls the oracle's _jadd/_jdouble through the module so tests can count them."""
    k %= N
    kp = k + N
    if kp.bit_length() <= 256:
        kp += N
    j = _oracle._to_jac(pt)
    r0, r1 = j, _oracle._jdouble(j)
    for i in range(255, -1, -1):
        if (kp >> i) & 1:
            r0, r1 = _oracle._jadd(r0, r1), _oracle._jdouble(r1)
        else:
            r1, r0 = _oracle._jadd(r0, r1), _oracle._jdouble(r0)
    return _oracle._to_affine(r0)


def pubkey(secret: int) -> bytes:
    """Compressed SEC1 public key."""
    if BACKEND == "coincurve":
        return PrivateKey(secret.to_bytes(32, "big")).public_key.format(compressed=True)
    x, y = _mul_secret(secret)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def ecdh(secret: int, pub: bytes) -> bytes:
    """x coordinate of secret * pub (32 bytes): a secret both channel parties can compute."""
    if BACKEND == "coincurve":
        return PublicKey(pub).multiply(secret.to_bytes(32, "big")).format(compressed=True)[1:]
    return _mul_secret(secret, _decode_pub(pub))[0].to_bytes(32, "big")


def sign(secret: int, msg32: bytes) -> bytes:
    """DER signature (low-S) over a 32-byte digest, without the hash-type byte. Both backends use
    RFC 6979 nonces, so both give the same bytes."""
    if BACKEND == "coincurve":
        return PrivateKey(secret.to_bytes(32, "big")).sign(msg32, hasher=None)
    z = int.from_bytes(msg32, "big")
    k = _oracle._rfc6979(secret, msg32)
    r = _mul_secret(k)[0] % N
    b = secrets.randbelow(N - 1) + 1                   # blind the nonce inversion
    s = pow(k * b % N, N - 2, N) * b * (z + r * secret) % N
    if s > N // 2:
        s = N - s
    body = _oracle._der_int(r) + _oracle._der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def verify(pub: bytes, msg32: bytes, der: bytes) -> bool:
    """Verify a strict-DER, low-S signature: exactly what the node accepts in a segwit v0 witness."""
    if not is_strict_der(der):
        return False
    if BACKEND == "coincurve":
        try:
            return bool(PublicKey(pub).verify(der, msg32, hasher=None))
        except Exception:
            return False
    return _oracle.verify(pub, msg32, der)
