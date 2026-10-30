"""Diffie-Hellman key exchange over Z_p* using a safe prime."""
import secrets
from number_theory import generate_safe_prime, modpow


def generate_params(bits: int = 256):
    """Demo: 256 bits. In real use, take RFC 7919 groups (>= 2048 bits)."""
    p = generate_safe_prime(bits)
    q = (p - 1) // 2
    # g = h^2 generates the prime-order q subgroup
    g = modpow(secrets.randbelow(p - 3) + 2, 2, p)
    return p, g, q



def generate_keypair(p: int, g: int, q: int):
    priv = secrets.randbelow(q - 1) + 1
    return priv, modpow(g, priv, p)


def shared_secret(p: int, priv: int, other_pub: int) -> int:
    if not 1 < other_pub < p - 1:
        raise ValueError("invalid publick key")
    return modpow(other_pub, priv, p)
