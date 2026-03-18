import time
import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def run_bench():
    iterations = 50
    # ECC
    t0 = time.perf_counter()
    for _ in range(iterations):
        ec.generate_private_key(ec.SECP256R1(), default_backend())
    ecc_kg = (time.perf_counter() - t0) / iterations * 1000

    aes_key = os.urandom(32)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    pt = b"Enter the text to be encrypted"
    
    t0 = time.perf_counter()
    for _ in range(iterations * 10):
        aesgcm.encrypt(nonce, pt, None)
    ecc_en = (time.perf_counter() - t0) / (iterations * 10) * 1000

    ct = aesgcm.encrypt(nonce, pt, None)
    t0 = time.perf_counter()
    for _ in range(iterations * 10):
        aesgcm.decrypt(nonce, ct, None)
    ecc_de = (time.perf_counter() - t0) / (iterations * 10) * 1000

    # RSA
    t0 = time.perf_counter()
    # RSA Keygen is slow, do only 10
    for _ in range(10):
        rsa.generate_private_key(65537, 2048, default_backend())
    rsa_kg = (time.perf_counter() - t0) / 10 * 1000

    priv = rsa.generate_private_key(65537, 2048, default_backend())
    pub = priv.public_key()
    
    t0 = time.perf_counter()
    for _ in range(iterations * 2):
        pub.encrypt(pt, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    rsa_en = (time.perf_counter() - t0) / (iterations * 2) * 1000

    ct_rsa = pub.encrypt(pt, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    t0 = time.perf_counter()
    for _ in range(iterations * 2):
        priv.decrypt(ct_rsa, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    rsa_de = (time.perf_counter() - t0) / (iterations * 2) * 1000

    print(f"RESULT|{ecc_kg:.3f}|{ecc_en:.3f}|{ecc_de:.3f}|{rsa_kg:.3f}|{rsa_en:.3f}|{rsa_de:.3f}")

if __name__ == "__main__":
    run_bench()
