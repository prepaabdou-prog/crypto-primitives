import secrets
import number_theory as nt
import rsa, diffie_hellman as dh, ecc


def test_number_theory():
    assert nt.gcd(48, 18) == 6
    g, x, y = nt.egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2
    assert nt.modinv(3, 11) == 4
    assert nt.modpow(7, 560, 561) == pow(7, 560, 561)
    assert nt.crt([2, 3, 2], [3, 5, 7]) == 23
    assert nt.is_probable_prime(2**127 - 1) and not nt.is_probable_prime(561)  # 561 = Carmicheal
    assert nt.generate_prime(128).bit_length() == 128



def test_rsa():
    pub, priv = rsa.generate_keypair(1024)
    m = b"hello PKCS1"
    assert rsa.pkcs1_decrypt(priv, rsa.pkcs1_encrypt(pub, m)) == m
    assert rsa.pkcs1_encrypt(pub, m) != rsa.pkcs1_encrypt(pub, m)  # random padding
    sig = rsa.sign(priv, m)
    assert rsa.verify(pub, m, sig) and not rsa.verify(pub, b"other", sig)
    c = secrets.randbelow(pub.n)
    assert rsa.decrypt_raw_crt(priv, c) == pow(c, priv.d, pub.n)


def test_dh():
    p, g, q = dh.generate_params(128)
    a, A = dh.generate_keypair(p, g, q)
    b, B = dh.generate_keypair(p, g, q)
    assert dh.shared_secret(p, a, B) == dh.shared_secret(p, b, A)


def test_ecc():
    C = ecc.SECP256K1
    assert C.contains(C.G)
    assert C.mul(C.n, C.G) is ecc.INF            # n*G = infinity
    k = secrets.randbelow(C.n)
    assert C.mul(k, C.G) == C.mul_ladder(k, C.G)
    a, A = ecc.generate_keypair()
    b, B = ecc.generate_keypair()
    assert ecc.ecdh(C, a, B) == ecc.ecdh(C, b, A)
    sig = ecc.ecdsa_sign(C, a, b"msg")
    assert ecc.ecdsa_verify(C, A, b"msg", sig)
    assert not ecc.ecdsa_verify(C, A, b"other", sig)


if __name__ == "__main__":
    for t in (test_number_theory, test_rsa, test_dh, test_ecc):
        t()
        print("OK", t.__name__)
