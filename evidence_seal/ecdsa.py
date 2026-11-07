"""ECDSA verification in pure Python for the NIST P-256, P-384 and P-521 curves.

Only public values are involved, so plain Python integers are fine. Points use
Jacobian coordinates, which avoids a modular inverse on every addition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from . import oids

Point = Optional[Tuple[int, int]]


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def size(self) -> int:
        return (self.p.bit_length() + 7) // 8

    @property
    def generator(self) -> Tuple[int, int]:
        return (self.gx, self.gy)

    def contains(self, x: int, y: int) -> bool:
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


P256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
P384 = Curve(
    "P-384",
    p=(1 << 384) - (1 << 128) - (1 << 96) + (1 << 32) - 1,
    a=-3,
    b=int(
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        16,
    ),
    gx=int(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
        "5502F25DBF55296C3A545E3872760AB7",
        16,
    ),
    gy=int(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
        16,
    ),
    n=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
)
P521 = Curve(
    "P-521",
    p=(1 << 521) - 1,
    a=-3,
    b=int(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
        "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
        "3F00",
        16,
    ),
    gx=int(
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
        "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
        "BD66",
        16,
    ),
    gy=int(
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
        "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
        "6650",
        16,
    ),
    n=int(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138"
        "6409",
        16,
    ),
)
CURVES: Dict[str, Curve] = {oids.CURVE_P256: P256, oids.CURVE_P384: P384, oids.CURVE_P521: P521}

_Jacobian = Tuple[int, int, int]
_INFINITY: _Jacobian = (1, 1, 0)


def _double(curve: Curve, point: _Jacobian) -> _Jacobian:
    x, y, z = point
    if z == 0 or y == 0:
        return _INFINITY
    p = curve.p
    yy = y * y % p
    s = 4 * x * yy % p
    zz = z * z % p
    m = 3 * (x - zz) * (x + zz) % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * yy * yy) % p
    z3 = 2 * y * z % p
    return (x3, y3, z3)


def _add(curve: Curve, one: _Jacobian, two: _Jacobian) -> _Jacobian:
    x1, y1, z1 = one
    x2, y2, z2 = two
    if z1 == 0:
        return two
    if z2 == 0:
        return one
    p = curve.p
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    if u1 == u2:
        if s1 != s2:
            return _INFINITY
        return _double(curve, one)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    z3 = h * z1 * z2 % p
    return (x3, y3, z3)


def _to_affine(curve: Curve, point: _Jacobian) -> Point:
    x, y, z = point
    if z == 0:
        return None
    inverse = pow(z, curve.p - 2, curve.p)
    zz = inverse * inverse % curve.p
    return (x * zz % curve.p, y * zz * inverse % curve.p)


def scalar_multiply(curve: Curve, scalar: int, point: Tuple[int, int]) -> Point:
    """Plain double-and-add. Used for public values only."""
    result = _INFINITY
    base: _Jacobian = (point[0], point[1], 1)
    for bit in bin(scalar)[2:]:
        result = _double(curve, result)
        if bit == "1":
            result = _add(curve, result, base)
    return _to_affine(curve, result)


def _combine(curve: Curve, u1: int, u2: int, q: Tuple[int, int]) -> Point:
    """Computes u1*G + u2*Q with one shared chain of doublings."""
    g_jac: _Jacobian = (curve.gx, curve.gy, 1)
    q_jac: _Jacobian = (q[0], q[1], 1)
    both = _add(curve, g_jac, q_jac)
    table = {(0, 0): _INFINITY, (1, 0): g_jac, (0, 1): q_jac, (1, 1): both}
    result = _INFINITY
    for bit in range(max(u1.bit_length(), u2.bit_length()) - 1, -1, -1):
        result = _double(curve, result)
        entry = table[((u1 >> bit) & 1, (u2 >> bit) & 1)]
        result = _add(curve, result, entry)
    return _to_affine(curve, result)


def decode_point(curve: Curve, encoded: bytes) -> Tuple[int, int]:
    """Decodes an uncompressed or compressed public point and checks it is on the curve."""
    size = curve.size
    if len(encoded) == 2 * size + 1 and encoded[0] == 4:
        x = int.from_bytes(encoded[1:size + 1], "big")
        y = int.from_bytes(encoded[size + 1:], "big")
    elif len(encoded) == size + 1 and encoded[0] in (2, 3):
        x = int.from_bytes(encoded[1:], "big")
        # All three curves have p = 3 mod 4, so the square root has a closed form.
        y = pow((x * x * x + curve.a * x + curve.b) % curve.p, (curve.p + 1) // 4, curve.p)
        if y & 1 != encoded[0] & 1:
            y = curve.p - y
    else:
        raise ValueError("unsupported elliptic curve point encoding")
    if not curve.contains(x, y) or (x == 0 and y == 0):
        raise ValueError("public key point is not on the curve")
    return (x, y)


def verify(curve: Curve, q: Tuple[int, int], digest: bytes, r: int, s: int) -> bool:
    """Standard ECDSA verification, FIPS 186 section 6.4.2."""
    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
        e >>= excess
    w = pow(s, n - 2, n)
    point = _combine(curve, e * w % n, r * w % n, q)
    if point is None:
        return False
    return point[0] % n == r
