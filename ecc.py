
from dataclasses import dataclass
from typing import Optional, Tuple
from utils import modinv, randbytes


# ---------- Curve parameters ----------
# Finite field prime
P_FIELD = 11

# Curve coefficients
A_CURVE = 1
B_CURVE = 6


# ---------- Point representation ----------
@dataclass(frozen=True)
class ECPoint:
    """
    Represents a point (x, y) on the elliptic curve.
    """
    x: int
    y: int


# Point at infinity (identity element)
O: Optional[ECPoint] = None


def is_on_curve(pt: Optional[ECPoint]) -> bool:
    """
    Check whether a point lies on the elliptic curve
    or is the point at infinity.
    """
    if pt is O:
        return True
    x = pt.x % P_FIELD
    y = pt.y % P_FIELD
    return (y * y - (x * x * x + A_CURVE * x + B_CURVE)) % P_FIELD == 0


def point_neg(pt: Optional[ECPoint]) -> Optional[ECPoint]:
    """
    Return the additive inverse of a point:
    (x, y) -> (x, -y mod p)
    """
    if pt is O:
        return O
    return ECPoint(pt.x % P_FIELD, (-pt.y) % P_FIELD)


def point_add(p1: Optional[ECPoint], p2: Optional[ECPoint]) -> Optional[ECPoint]:
    """
    Add two elliptic curve points according to the rules:
    1) P + O = P
    2) P + (-P) = O
    3) P != Q  : regular addition
    4) P == Q  : point doubling
    """
    # Identity element cases
    if p1 is O:
        return p2
    if p2 is O:
        return p1

    x1, y1 = p1.x % P_FIELD, p1.y % P_FIELD
    x2, y2 = p2.x % P_FIELD, p2.y % P_FIELD

    # P + (-P) = O
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return O

    # Compute slope m
    if x1 == x2 and y1 == y2:
        # Point doubling
        if y1 == 0:
            return O
        m = ((3 * x1 * x1 + A_CURVE) *
             modinv((2 * y1) % P_FIELD, P_FIELD)) % P_FIELD
    else:
        # Regular addition
        denom = (x2 - x1) % P_FIELD
        m = ((y2 - y1) * modinv(denom, P_FIELD)) % P_FIELD

    # Resulting point
    xr = (m * m - x1 - x2) % P_FIELD
    yr = (m * (x1 - xr) - y1) % P_FIELD
    return ECPoint(xr, yr)


def scalar_mult(k: int, pt: Optional[ECPoint]) -> Optional[ECPoint]:
    """
    Compute scalar multiplication k * P
    using the double-and-add algorithm.
    """
    if pt is O or k == 0:
        return O
    if k < 0:
        return scalar_mult(-k, point_neg(pt))

    result = O
    addend = pt

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def keygen(base_point: ECPoint) -> Tuple[int, ECPoint]:
    """
    Generate an ECC key pair:
    - Private key: integer d
    - Public key: Q = d * base_point
    """
    d = int.from_bytes(randbytes(2), "big") % P_FIELD
    if d == 0:
        d = 1

    Q = scalar_mult(d, base_point)
    if Q is O:
        raise RuntimeError("Invalid public key (point at infinity)")

    return d, Q
