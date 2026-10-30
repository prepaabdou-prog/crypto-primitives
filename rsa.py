"""RSA: key generation, PKCS#1 v1.5 padding, encryption, signature and CRT.
For learning use only, dont use in production."""
import hashlib
import secrets
from dataclasses import dataclass
from number_theory import generate_prime, modinv, modpow, gcd


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int
    p: int
    q: int


def generate_keypair(bits: int = 2048, e: int = 65537):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break
    n = p * q
    d = modinv(e, phi)
    return PublicKey(n, e), PrivateKey(n, d, p, q)


def _k(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _i2b(x: int, k: int) -> bytes:
    return x.to_bytes(k, "big")


def _b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def decrypt_raw_crt(priv: PrivateKey, c: int) -> int:
    """Decryption using CRT: about 4x faster than pow(c, d, n)."""
    dp, dq = priv.d % (priv.p - 1), priv.d % (priv.q - 1)
    m1, m2 = modpow(c, dp, priv.p), modpow(c, dq, priv.q)
    h = modinv(priv.q, priv.p) * (m1 - m2) % priv.p
    return m2 + h * priv.q


# --- PKCS#1 v1.5 encryption: 00 02 PS(non-zero, random) 00 M ---
def pkcs1_encrypt(pub: PublicKey, msg: bytes) -> bytes:
    k = _k(pub.n)
    if len(msg) > k - 11:
        raise ValueError("message is too long")
    ps = bytes(secrets.choice(range(1, 256)) for _ in range(k - len(msg) - 3))
    em = b"\x00\x02" + ps + b"\x00" + msg
    return _i2b(modpow(_b2i(em), pub.e, pub.n), k)


def pkcs1_decrypt(priv: PrivateKey, ct: bytes) -> bytes:
    k = _k(priv.n)
    em = _i2b(decrypt_raw_crt(priv, _b2i(ct)), k)
    if em[0:2] != b"\x00\x02" or b"\x00" not in em[2:]:
        raise ValueError("invalid paddding")
    return em[em.index(b"\x00", 2) + 1:]


# --- PKCS#1 v1.5 signature (SHA-256): 00 01 FF..FF 00 DigestInfo ---
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _sig_encode(msg: bytes, k: int) -> bytes:
    t = _SHA256_PREFIX + hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign(priv: PrivateKey, msg: bytes) -> bytes:
    k = _k(priv.n)
    return _i2b(decrypt_raw_crt(priv, _b2i(_sig_encode(msg, k))), k)


def verify(pub: PublicKey, msg: bytes, sig: bytes) -> bool:
    k = _k(pub.n)
    em = _i2b(modpow(_b2i(sig), pub.e, pub.n), k)
    return em == _sig_encode(msg, k)
