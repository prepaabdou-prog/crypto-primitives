"""Elliptic curves y^2 = x^3 + ax + b over F_p: arithmetics, ECDH and ECDSA."""
import hashlib
import secrets
from dataclasses import dataclass
from number_theory import modinv

INF = None  # point at infinty


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int
    G: tuple
    n: int  # order of G

    def contains(self, P) -> bool:
        if P is INF:
            return True
        x, y = P
        return (y * y - (x ** 3 + self.a * x + self.b)) % self.p == 0

    def neg(self, P):
        return INF if P is INF else (P[0], (-P[1]) % self.p)

    def add(self, P, Q):
        if P is INF:
            return Q
        if Q is INF:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return INF
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * modinv(2 * y1, self.p) % self.p
        else:
             lam = (y2 - y1) * modinv(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        return (x3, (lam * (x1 - x3) - y1) % self.p)

    def mul(self, k: int, P):
        """Double-and-add (NOT constant-time)."""
        if k < 0:
            return self.mul(-k, self.neg(P))
        R, Q = INF, P
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    def mul_ladder(self, k: int, P):
        """Montgomery ladder: same operation sequence for each bit."""
        R0, R1 = INF, P
        for i in reversed(range(k.bit_length())):
            if (k >> i) & 1:
                R0, R1 = self.add(R0, R1), self.add(R1, R1)
            else:
                R1, R0 = self.add(R0, R1), self.add(R0, R0)
        return R0


SECP256K1 = Curve(
    p=2**256 - 2**32 - 977,
    a=0,
    b=7,
    G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)



def generate_keypair(curve: Curve = SECP256K1):
    d = secrets.randbelow(curve.n - 1) + 1
    return d, curve.mul_ladder(d, curve.G)


def ecdh(curve: Curve, priv: int, other_pub) -> bytes:
    if other_pub is INF or not curve.contains(other_pub):
        raise ValueError("invalid pointt")
    S = curve.mul_ladder(priv, other_pub)
    return hashlib.sha256(S[0].to_bytes(32, "big")).digest()


def _h(msg: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n


def ecdsa_sign(curve: Curve, d: int, msg: bytes):
    z = _h(msg, curve.n)
    while True:
        k = secrets.randbelow(curve.n - 1) + 1
        r = curve.mul_ladder(k, curve.G)[0] % curve.n
        s = modinv(k, curve.n) * (z + r * d) % curve.n
        if r and s:
            return r, s


def ecdsa_verify(curve: Curve, pub, msg: bytes, sig) -> bool:
    r, s = sig
    if not (0 < r < curve.n and 0 < s < curve.n):
        return False
    z, w = _h(msg, curve.n), modinv(s, curve.n)
    P = curve.add(curve.mul(z * w % curve.n, curve.G), curve.mul(r * w % curve.n, pub))
    return P is not INF and P[0] % curve.n == r
