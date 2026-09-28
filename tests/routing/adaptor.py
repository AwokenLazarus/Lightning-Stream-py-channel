"""ECDSA adaptor signatures for adaptor-locked xbt402 states (AGP-019 hub routing, tests only).

Vendored from b5 `agp-014` `fwd/adaptor.py` (the AGP-008/014 construction), without the MuSig2 parts,
on this tree's point helpers. A payer pre-signs its next channel state under a point Y. The
pre-signature is not a valid ECDSA signature: whoever knows y (Y = y*G) completes it into one,
and whoever holds the pre-signature and sees the completed signature learns y.

    pre-sign(x, z, Y):  k random; R' = k*G; R = k*Y; r = R.x mod n; s' = k^-1 (z + r*x)
                        pi = DLEQ proof that log_G(R') = log_Y(R)
    pre-verify:         pi holds and s'^-1 (z*G + r*X) == R'
    adapt(y):           s = s' * y^-1, low-S          -> (r, s) is a valid ECDSA signature
    extract(s):         y = +-(s' * s^-1), the sign fixed by y*G == Y

Pure Python (Fournier 2019; Aumayr et al. 2021). Secret scalar multiplications use B1's
fixed-sequence ladder, the rest is not constant time. Production uses libsecp256k1-zkp's
ecdsa_adaptor module.
"""
import secrets
from dataclasses import dataclass
from typing import Optional

from xbt402 import ecc_oracle as ecc
from xbt402.ecc import _mul_secret
from xbt402.tx import tagged_hash

N, P, G = ecc.N, ecc.P, ecc.G


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def enc(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def dec(b: bytes):
    return ecc._decode_pub(b)


def _neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def point_of(y: int):
    return ecc._mul(y % N)


def add(a, b):
    return ecc._add(a, b)


def _challenge(X: bytes, z: bytes, Y, R1, R, A1, A2) -> int:
    return _int(tagged_hash("b5/adaptor/dleq", X + z + enc(Y) + enc(R1) + enc(R) + enc(A1) + enc(A2))) % N


@dataclass
class PreSig:
    R: bytes      # k*Y: r = R.x mod n is the r of the completed signature
    R1: bytes     # k*G
    s1: int       # s' = k^-1 (z + r*x)
    c: int        # DLEQ challenge
    zz: int       # DLEQ response

    @property
    def r(self) -> int:
        return dec(self.R)[0] % N

    def to_json(self) -> dict:
        return {"R": self.R.hex(), "R1": self.R1.hex(), "s1": f"{self.s1:064x}",
                "c": f"{self.c:064x}", "z": f"{self.zz:064x}"}

    def bogus_der(self) -> bytes:
        """(r, s') as if it were a signature: what a payee that never learns y could try to close with."""
        return der(self.r, min(self.s1, N - self.s1))


def presign(x: int, z: bytes, Y) -> PreSig:
    X = enc(_mul_secret(x))
    zi = _int(z)
    while True:
        k = secrets.randbelow(N - 1) + 1
        R1, R = _mul_secret(k), _mul_secret(k, Y)
        r = R[0] % N
        s1 = pow(k, N - 2, N) * (zi + r * x) % N
        if r and s1:
            w = secrets.randbelow(N - 1) + 1
            A1, A2 = _mul_secret(w), _mul_secret(w, Y)
            c = _challenge(X, z, Y, R1, R, A1, A2)
            return PreSig(enc(R), enc(R1), s1, c, (w + c * k) % N)


def preverify(X: bytes, z: bytes, Y, pre: PreSig) -> bool:
    """True iff completing `pre` with log_G(Y) gives a valid ECDSA signature by X over z."""
    try:
        R, R1, Xp = dec(pre.R), dec(pre.R1), dec(X)
    except (ValueError, TypeError):
        return False
    if not (0 <= pre.c < N and 0 < pre.zz < N and 0 < pre.s1 < N):
        return False
    A1 = add(ecc._mul(pre.zz), _neg(ecc._mul(pre.c, R1)))
    A2 = add(ecc._mul(pre.zz, Y), _neg(ecc._mul(pre.c, R)))
    if A1 is None or A2 is None or pre.c != _challenge(X, z, Y, R1, R, A1, A2):
        return False
    r = R[0] % N
    if not r:
        return False
    si = pow(pre.s1, N - 2, N)
    return add(ecc._mul(_int(z) * si % N), ecc._mul(r * si % N, Xp)) == R1


def _der_int(i: int) -> bytes:
    b = i.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def parse_der(sig: bytes):
    if len(sig) < 8 or sig[0] != 0x30 or sig[1] != len(sig) - 2 or sig[2] != 0x02:
        raise ValueError("not DER")
    lr = sig[3]
    if sig[4 + lr] != 0x02:
        raise ValueError("not DER")
    ls = sig[5 + lr]
    return _int(sig[4:4 + lr]), _int(sig[6 + lr:6 + lr + ls])


def adapt(pre: PreSig, y: int) -> bytes:
    """The completed low-S strict-DER signature (no hash-type byte)."""
    y %= N
    if not y:
        raise ValueError("zero adaptor secret")
    s = pre.s1 * pow(y, N - 2, N) % N
    return der(pre.r, N - s if s > N // 2 else s)


def extract(pre: PreSig, sig: bytes, Y) -> Optional[int]:
    """y from a completed signature (with or without the hash-type byte), or None if `sig` is not a
    completion of `pre`."""
    if sig and len(sig) == sig[1] + 3:
        sig = sig[:-1]
    try:
        r, s = parse_der(sig)
    except (ValueError, IndexError):
        return None
    if r != pre.r or not 0 < s < N:
        return None
    y = pre.s1 * pow(s, N - 2, N) % N
    return next((c for c in (y, N - y) if point_of(c) == Y), None)
