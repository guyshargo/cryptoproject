
from dataclasses import dataclass
from typing import Optional, Tuple
from utils import modinv, randbytes


@dataclass(frozen=True)
class ECPoint:
    """Represents a point on an elliptic curve."""
    x: int
    y: int


class EllipticCurve:
    """
    Elliptic curve over a finite field:
        y^2 = x^3 + a*x + b (mod p)
    """

    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b

    # ---------- Basic checks ----------
    def is_on_curve(self, pt: Optional[ECPoint]) -> bool:
        if pt is None:
            return True
        x, y = pt.x % self.p, pt.y % self.p
        return (y*y - (x*x*x + self.a*x + self.b)) % self.p == 0

    # ---------- Point operations ----------
    def point_neg(self, pt: Optional[ECPoint]) -> Optional[ECPoint]:
        if pt is None:
            return None
        return ECPoint(pt.x % self.p, (-pt.y) % self.p)

    def point_add(self, p1: Optional[ECPoint],
                  p2: Optional[ECPoint]) -> Optional[ECPoint]:

        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1.x % self.p, p1.y % self.p
        x2, y2 = p2.x % self.p, p2.y % self.p

        # P + (-P) = O
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        # Compute slope
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None
            m = ((3*x1*x1 + self.a) *
                 modinv((2*y1) % self.p, self.p)) % self.p
        else:
            m = ((y2 - y1) *
                 modinv((x2 - x1) % self.p, self.p)) % self.p

        xr = (m*m - x1 - x2) % self.p
        yr = (m*(x1 - xr) - y1) % self.p
        return ECPoint(xr, yr)

    # ---------- Scalar multiplication ----------
    def scalar_mult(self, k: int,
                    pt: Optional[ECPoint]) -> Optional[ECPoint]:

        if pt is None or k == 0:
            return None
        if k < 0:
            return self.scalar_mult(-k, self.point_neg(pt))

        result = None
        addend = pt

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    # ---------- Key generation ----------
    def keygen(self, base_point: ECPoint) -> Tuple[int, ECPoint]:
        d = int.from_bytes(randbytes(4), "big") % self.p
        if d == 0:
            d = 1

        Q = self.scalar_mult(d, base_point)
        if Q is None:
            raise RuntimeError("Invalid public key")

        return d, Q
