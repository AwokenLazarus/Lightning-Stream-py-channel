"""ECDSA adaptor signatures for adaptor-locked xbt402 states (AGP-021 hub routing, from AGP-019).

A payer pre-signs its next channel state under a point Y. The pre-signature is not a valid ECDSA
signature: whoever knows y (Y = y*G) completes it into one, and whoever holds the pre-signature and
sees the completed signature learns y. The completed signature is an ordinary 0x21 state signature,
so B1's Payee, close and watcher take it unchanged.

    pre-sign(x, z, Y):  k random; R' = k*G; R = k*Y; r = R.x mod n; s' = k^-1 (z + r*x)
                        pi = DLEQ proof that log_G(R') = log_Y(R)
    pre-verify:         pi holds and s'^-1 (z*G + r*X) == R'
    adapt(y):           s = s' * y^-1, low-S          -> (r, s) is a valid ECDSA signature
    extract(s):         y = +-(s' * s^-1), the sign fixed by y*G == Y

The construction and wire encoding are AGP-008/014's (b5 `fwd/adaptor.py`, B2
`agentwallet/fwd/adaptor.py`), so a B2 pre-signature verifies here and the other way round.

Crypto backend (AGP-021 item 4). No libsecp256k1-zkp binding (its `ecdsa_adaptor` module) is
installed on this host or packaged for this venv, so this is the existing adaptor after a
constant-time review:
  * every multiplication of a point by a SECRET scalar (the key x, the nonce k, the DLEQ nonce w)
    runs in libsecp256k1 through coincurve (`secp256k1_ec_pubkey_create`/`_tweak_mul`, both
    constant time) when coincurve is installed, else in B1's fixed-sequence Montgomery ladder
    (`ecc._mul_secret`, XBT-061 H4);
  * every modular inversion of a secret (k^-1 in pre-sign, y^-1 in adapt) is blinded by a fresh
    random factor b: a^-1 = b * (a*b)^-1, so the exponentiation never sees the secret itself;
  * the remaining secret arithmetic, s' = k^-1 (z + r*x) and the DLEQ response w + c*k, are single
    Python big-integer products and sums mod n. Their running time depends on operand sizes only,
    which leaks at most a few bits of magnitude to an attacker who can time this process locally;
    x and k are blinded in the same way before they are multiplied (below);
  * public-data work (pre-verify, extract, point sums) needs no constant time and runs in
    libsecp256k1 when available, for speed: one routed lock (both hops) costs a few ms instead of
    AGP-019's 33 ms.
Swapping in libsecp256k1-zkp later changes this module only: the encoding is the same.
"""
import secrets
from dataclasses import dataclass
from typing import Optional

from . import ecc as _ecc
from . import ecc_oracle as _oracle
from .tx import tagged_hash

N, P, G = _oracle.N, _oracle.P, _oracle.G

try:
    from coincurve import PrivateKey as _CPriv, PublicKey as _CPub
except ImportError:          # pragma: no cover - the fallback path is exercised by forcing BACKEND
    _CPriv = _CPub = None


def _cc() -> bool:
    return _CPub is not None and _ecc.BACKEND == "coincurve"


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def enc(pt) -> bytes:
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def dec(b: bytes):
    """A compressed point as (x, y). Raises ValueError for anything that is not on the curve."""
    if isinstance(b, str):
        b = bytes.fromhex(b)
    return _oracle._decode_pub(b)


def _neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def _from_cc(pk):
    return pk.point()


def _mul_pub(k: int, pt=None):
    """k*pt (pt = G by default) for a PUBLIC scalar; None for the point at infinity."""
    k %= N
    if not k:
        return None
    if _cc():
        if pt is None:
            return _from_cc(_CPriv(k.to_bytes(32, "big")).public_key)
        return _from_cc(_CPub(enc(pt)).multiply(k.to_bytes(32, "big")))
    return _oracle._mul(k, pt) if pt is not None else _oracle._mul(k)


def _mul_secret(k: int, pt=None):
    """k*pt for a SECRET scalar, constant time (libsecp256k1, or B1's fixed-sequence ladder)."""
    k %= N
    if not k:
        raise ValueError("zero scalar")
    if _cc():
        if pt is None:
            return _from_cc(_CPriv(k.to_bytes(32, "big")).public_key)
        return _from_cc(_CPub(enc(pt)).multiply(k.to_bytes(32, "big")))
    return _ecc._mul_secret(k) if pt is None else _ecc._mul_secret(k, pt)


def point_of(y: int):
    """y*G. y is a secret here (a route's t or t + r)."""
    return _mul_secret(y)


def add(a, b):
    """a + b for public points; None at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    if _cc():
        try:
            return _from_cc(_CPub.combine_keys([_CPub(enc(a)), _CPub(enc(b))]))
        except ValueError:
            return None
    return _oracle._add(a, b)


def _inv_blinded(a: int) -> int:
    """a^-1 mod n for a secret a, blinded: the exponentiation only ever sees a*b for a fresh b."""
    b = secrets.randbelow(N - 1) + 1
    return b * pow(a * b % N, N - 2, N) % N


def _challenge(X: bytes, z: bytes, Y, R1, R, A1, A2) -> int:
    return _int(tagged_hash("b5/adaptor/dleq", X + z + enc(Y) + enc(R1) + enc(R) + enc(A1) + enc(A2))) % N


def _scalar(v) -> int:
    return int(v, 16) if isinstance(v, str) else int(v)


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

    @classmethod
    def from_json(cls, d: dict) -> "PreSig":
        """Parse the wire form. Raises ValueError/KeyError/TypeError on anything malformed."""
        if not isinstance(d, dict):
            raise TypeError("adaptor must be an object")
        R, R1 = bytes.fromhex(d["R"]), bytes.fromhex(d["R1"])
        if len(R) != 33 or len(R1) != 33:
            raise ValueError("adaptor points are 33-byte compressed")
        vals = []
        for k in ("s1", "c", "z"):
            s = d[k]
            if not isinstance(s, str) or len(s) != 64:
                raise ValueError(f"adaptor {k} is 64 hex")
            vals.append(int(s, 16))
        return cls(R, R1, *vals)

    def bogus_der(self) -> bytes:
        """(r, s') as if it were a signature: what a payee that never learns y could try to close with."""
        return der(self.r, min(self.s1, N - self.s1))


def presign(x: int, z: bytes, Y) -> PreSig:
    """Pre-sign digest z with key x under point Y (a secret-key operation: see the module note)."""
    X = enc(_mul_secret(x))
    zi = _int(z)
    while True:
        k = secrets.randbelow(N - 1) + 1
        R1, R = _mul_secret(k), _mul_secret(k, Y)
        r = R[0] % N
        # s' = k^-1 (z + r x): x enters as x*b + ... with a fresh blind b (then b^-1), so the product
        # r*x is never computed on the raw key
        b = secrets.randbelow(N - 1) + 1
        rx = r * (x * b % N) % N * pow(b, N - 2, N) % N
        s1 = _inv_blinded(k) * ((zi + rx) % N) % N
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
    try:
        A1 = add(_mul_pub(pre.zz), _neg(_mul_pub(pre.c, R1)))
        A2 = add(_mul_pub(pre.zz, Y), _neg(_mul_pub(pre.c, R)))
    except (ValueError, TypeError):
        return False
    if A1 is None or A2 is None or pre.c != _challenge(X, z, Y, R1, R, A1, A2):
        return False
    r = R[0] % N
    if not r:
        return False
    si = pow(pre.s1, N - 2, N)
    return add(_mul_pub(_int(z) * si % N), _mul_pub(r * si % N, Xp)) == R1


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
    """The completed low-S strict-DER signature (no hash-type byte). y is secret: blinded inverse."""
    y %= N
    if not y:
        raise ValueError("zero adaptor secret")
    s = pre.s1 * _inv_blinded(y) % N
    return der(pre.r, N - s if s > N // 2 else s)


def extract(pre: PreSig, sig: bytes, Y) -> Optional[int]:
    """y from a completed signature (with or without the hash-type byte), or None if `sig` is not a
    completion of `pre`."""
    if sig and len(sig) >= 2 and len(sig) == sig[1] + 3:
        sig = sig[:-1]
    try:
        r, s = parse_der(sig)
    except (ValueError, IndexError):
        return None
    if r != pre.r or not 0 < s < N:
        return None
    y = pre.s1 * pow(s, N - 2, N) % N
    return next((c for c in (y, N - y) if _mul_pub(c) == Y), None)


def secret_from_witness(pre: PreSig, witness, Y) -> Optional[int]:
    """y from a close's input witness: any item that is a completion of `pre` (the payer signature
    is witness[0] in B1's pay path)."""
    for item in witness or []:
        y = extract(pre, bytes(item), Y)
        if y is not None:
            return y
    return None
