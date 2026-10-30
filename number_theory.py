"""Number theory: basic building blocks for RSA, DH and ECC."""
import secrets


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a: int, b: int):
    """Extended Euclid: returns (g, x, y) where a*x + b*y = g."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse (a and m are not coprime)")
    return x % m


def modpow(base: int, exp: int, mod: int) -> int:
    """Fast exponentiation (square-and-multiply)."""
    result, base = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def crt(residues, moduli) -> int:
    """Chinese remainder theorem (pairwise coprime moduli)."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M


_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin test."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = modpow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def generate_safe_prime(bits: int) -> int:
    """p = 2q + 1 where p and q are prime."""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_probable_prime(p):
            return p
