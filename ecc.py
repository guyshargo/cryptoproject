from dataclasses import dataclass
from typing import Optional, Tuple
from utils import modinv, randbytes, int_from_bytes

# ---------- Point representation ----------
@dataclass(frozen=True)
class ECPoint:
    """Represents a point on an elliptic curve."""
    x: int
    y: int

# Point at infinity (identity element)
O: Optional[ECPoint] = None


class EllipticCurve:
    """
    Elliptic curve over a finite field:
        y^2 = x^3 + a*x + b (mod p)
    """

    def __init__(self, p: int, a: int, b: int, n: int):
        self.p = p
        self.a = a
        self.b = b
        self.n = n # Order of the group (added for secure keygen)

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
        return ECPoint(pt.x % self.p, (self.p - pt.y) % self.p)

    def point_add(self, p1: Optional[ECPoint],
                  p2: Optional[ECPoint]) -> Optional[ECPoint]:

        if p1 is None: return p2
        if p2 is None: return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            if y1 == 0:
                return None
            # Slope for doubling
            m = ((3*x1*x1 + self.a) *
                 modinv((2*y1) % self.p, self.p)) % self.p
        else:
            # Slope for addition
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
        # FIXED: Generating 32 bytes (256 bits) instead of 4 bytes
        # Using the curve order (self.n) ensures uniform distribution
        d = int_from_bytes(randbytes(32)) % self.n
        if d == 0:
            d = 1

        Q = self.scalar_mult(d, base_point)
        if Q is None:
            raise RuntimeError("Invalid public key")

        return d, Q

# 1. Define Constants for Secp256k1
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# 2. Create the Curve Object
secp256k1 = EllipticCurve(_P, _A, _B, _N)

# 3. Export Global Variables (API for ec_elgamal.py)
# This makes the file compatible with your previous code
P = _P
A = _A
B = _B
N = _N
G = ECPoint(_GX, _GY)

# Wrapper functions that point to the secp256k1 instance
# This allows 'from ecc import scalar_mult' to work as expected
def scalar_mult(k, pt):
    return secp256k1.scalar_mult(k, pt)

def point_add(p1, p2):
    return secp256k1.point_add(p1, p2)

def point_neg(pt):
    return secp256k1.point_neg(pt)

def keygen(base_point=G):
    return secp256k1.keygen(base_point)