# crypto-primitives

Python implementations from scratch of classic cryptographic primitives, without crypto libraries (only `hashlib` and `secrets` from the standard library are used).

> ⚠️ **For educational use only.** The code is not constant-time and has not been audited. Do not use it in production.

## Content

| File | Content |
|---|---|
| `number_theory.py` | GCD, extended Euclid, modular inverse, square-and-multiply, CRT, Miller-Rabin, prime and safe-prime generation |
| `rsa.py` | Key generation, PKCS#1 v1.5 encryption, PKCS#1 v1.5 signature (SHA-256), CRT-accelerated decryption |
| `diffie_hellman.py` | Diffie-Hellman over a prime-order subgroup (safe prime) |
| `ecc.py` | Weierstrass curves over F_p: addition, doubling, double-and-add, Montgomery ladder, ECDH, ECDSA (secp256k1) |
| `test_all.py` | Tests (known vectors, math properties, round trips) |

## Runing the tests

```bash
python3 test_all.py
```

## Technical points

- **Miller-Rabin**: checked on 561 (a Carmichael number that fools the Fermat test).
- **RSA-CRT**: calculation modulo p and q seperately then recombination, about 4x faster than `pow(c, d, n)`.
- **PKCS#1 v1.5**: non-zero random padding, so two encryptions of the same message are different. This padding is vulnerable to Bleichenbacher's attack; OAEP is recomended in practice.
- **ECC**: `mul` (double-and-add) has a time depending on scalar bits; `mul_ladder` (Montgomery ladder) has a uniform operation sequence. This difference is the basis of the timing attack project on RSA/ECC.
- **Diffie-Hellman**: the generator is a square, so it generates the prime order q subgroup, avoiding a one-bit leak of the secret (Legendre).

## Known limits

- Python uses variable-size integers: no real constant-time.
- The ladder here protects the operation sequence, not memory acces or the time of integer operations.
- No complete curve validation (subgroup, twist).

## Ideas

- Timing attack against `mul` and countermeasure (ladder, blinding)
- RSA-OAEP and Bleichenbacher attack on PKCS#1 v1.5
- Ed25519 / Schnorr
