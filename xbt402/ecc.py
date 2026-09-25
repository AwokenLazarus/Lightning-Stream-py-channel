"""Minimal secp256k1 ECDSA: RFC 6979 nonces, low-S, DER.

Prototype only. This is pure Python and NOT constant time: fine for regtest and tests, never
for keys holding real value. Production swaps this module for libsecp256k1 (coincurve) behind
the same four functions.
"""
import hashlib
import hmac

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    """Affine point addition (None = infinity). Slow (one inversion); used only off the hot path."""
    if a is None:
        return b
    if b is None:
        return a
    return _to_affine(_jadd(_to_jac(a), _to_jac(b)))


# Jacobian coordinates (X, Y, Z) with x = X/Z^2, y = Y/Z^3; Z == 0 is infinity. No inversions
# until the end, which makes the pure-Python path ~10x faster than affine.
_INF = (0, 1, 0)


def _to_jac(pt):
    return _INF if pt is None else (pt[0], pt[1], 1)


def _to_affine(j):
    if j[2] == 0:
        return None
    zi = pow(j[2], P - 2, P)
    zi2 = zi * zi % P
    return j[0] * zi2 % P, j[1] * zi2 * zi % P


def _jdouble(j):
    X, Y, Z = j
    if Z == 0 or Y == 0:
        return _INF
    YY = Y * Y % P
    S = 4 * X * YY % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    return X3, (M * (S - X3) - 8 * YY * YY) % P, 2 * Y * Z % P


def _jadd(a, b):
    if a[2] == 0:
        return b
    if b[2] == 0:
        return a
    Z1Z1, Z2Z2 = a[2] * a[2] % P, b[2] * b[2] % P
    U1, U2 = a[0] * Z2Z2 % P, b[0] * Z1Z1 % P
    S1, S2 = a[1] * Z2Z2 * b[2] % P, b[1] * Z1Z1 * a[2] % P
    if U1 == U2:
        return _jdouble(a) if S1 == S2 else _INF
    H, R = (U2 - U1) % P, (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    return X3, (R * (V - X3) - S1 * HHH) % P, H * a[2] * b[2] % P


def _jmul(k, j):
    out = _INF
    for bit in bin(k)[2:]:
        out = _jdouble(out)
        if bit == "1":
            out = _jadd(out, j)
    return out


# Fixed-base table: 2^i * G, so k*G is additions only.
_GTABLE = []
_t = _to_jac(G)
for _ in range(256):
    _GTABLE.append(_t)
    _t = _jdouble(_t)


def _gmul_jac(k):
    out, i = _INF, 0
    while k:
        if k & 1:
            out = _jadd(out, _GTABLE[i])
        k >>= 1
        i += 1
    return out


def _mul(k, pt=G):
    k %= N
    if pt == G:
        return _to_affine(_gmul_jac(k))
    return _to_affine(_jmul(k, _to_jac(pt)))


def pubkey(secret: int) -> bytes:
    """Compressed SEC1 public key."""
    x, y = _mul(secret)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _decode_pub(pub: bytes):
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("compressed pubkey expected")
    x = int.from_bytes(pub[1:], "big")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("not on curve")
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return x, y


def _rfc6979(secret: int, msg32: bytes) -> int:
    x = secret.to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_int(i: int) -> bytes:
    b = i.to_bytes(32, "big").lstrip(b"\x00")
    if not b or b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign(secret: int, msg32: bytes) -> bytes:
    """DER signature (low-S) over a 32-byte digest, without the hash-type byte."""
    z = int.from_bytes(msg32, "big")
    k = _rfc6979(secret, msg32)
    r = _mul(k)[0] % N
    s = pow(k, N - 2, N) * (z + r * secret) % N
    if s > N // 2:
        s = N - s
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _parse_der(sig: bytes):
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2 or sig[2] != 2:
        raise ValueError("bad DER")
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    if sig[4 + rl] != 2:
        raise ValueError("bad DER")
    sl = sig[5 + rl]
    s = int.from_bytes(sig[6 + rl:6 + rl + sl], "big")
    if 6 + rl + sl != len(sig):
        raise ValueError("bad DER")
    return r, s


def verify(pub: bytes, msg32: bytes, der: bytes) -> bool:
    """Verify a DER signature; rejects high-S like the node's standardness rules."""
    try:
        r, s = _parse_der(der)
        pt = _decode_pub(pub)
    except ValueError:
        return False
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    w = pow(s, N - 2, N)
    z = int.from_bytes(msg32, "big")
    q = _to_affine(_jadd(_gmul_jac(z * w % N), _jmul(r * w % N, _to_jac(pt))))
    return q is not None and q[0] % N == r
