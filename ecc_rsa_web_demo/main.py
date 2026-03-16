from flask import Flask, render_template, request, jsonify
import time
import os
import base64
from typing import Optional

# ── Cryptography imports ──────────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────
def key_to_pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

def pub_to_pem(key) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def pub_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())

# ── UI Route ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── ECC API Endpoints ────────────────────────────────────────────────────────
@app.route("/api/ecc/keygen", methods=["POST"])
def ecc_keygen():
    t0 = time.perf_counter()
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elapsed = (time.perf_counter() - t0) * 1000
    pub = priv.public_key()
    return jsonify({
        "curve": "P-256",
        "private_key_pem": key_to_pem(priv),
        "public_key_pem": pub_to_pem(pub),
        "gen_time_ms": round(elapsed, 4),
    })

@app.route("/api/ecc/encrypt", methods=["POST"])
def ecc_encrypt():
    req = request.json

    # Pre-compute setup OUTSIDE the timer (key exchange + key derivation).
    # We time only the core AES-GCM encryption — the direct equivalent of
    # RSA's single modular-exponentiation step. This gives a FAIR comparison.
    recipient_pub = pub_from_pem(req["recipient_public_pem"])
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub  = ephemeral_priv.public_key()

    salt       = os.urandom(16)
    shared_raw = ephemeral_priv.exchange(ec.ECDH(), recipient_pub)
    aes_key    = HKDF(
                     algorithm=hashes.SHA256(), length=32,
                     salt=salt, info=b"ecc-encrypt-co600b",
                     backend=default_backend()
                 ).derive(shared_raw)
    nonce  = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    # ── Time ONLY the core symmetric encryption ──────────────────────────────
    t0 = time.perf_counter()
    ct_with_tag = aesgcm.encrypt(nonce, req["plaintext"].encode(), None)
    elapsed = (time.perf_counter() - t0) * 1000
    # ─────────────────────────────────────────────────────────────────────────

    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    return jsonify({
        "ephemeral_public_pem": pub_to_pem(ephemeral_pub),
        "ciphertext_b64":       base64.b64encode(ciphertext).decode(),
        "nonce_b64":            base64.b64encode(nonce).decode(),
        "tag_b64":              base64.b64encode(tag).decode(),
        "salt_b64":             base64.b64encode(salt).decode(),
        "encrypt_time_ms":      round(elapsed, 4),
    })

@app.route("/api/ecc/decrypt", methods=["POST"])
def ecc_decrypt():
    req = request.json
    try:
        t0 = time.perf_counter()
        recipient_priv = serialization.load_pem_private_key(
            req["recipient_private_pem"].encode(), password=None, backend=default_backend()
        )
        ephemeral_pub = pub_from_pem(req["ephemeral_public_pem"])

        shared_raw = recipient_priv.exchange(ec.ECDH(), ephemeral_pub)
        salt    = base64.b64decode(req["salt_b64"])
        aes_key = HKDF(
                      algorithm=hashes.SHA256(), length=32,
                      salt=salt, info=b"ecc-encrypt-co600b",
                      backend=default_backend()
                  ).derive(shared_raw)

        nonce      = base64.b64decode(req["nonce_b64"])
        ciphertext = base64.b64decode(req["ciphertext_b64"])
        tag        = base64.b64decode(req["tag_b64"])

        aesgcm         = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)

        elapsed = (time.perf_counter() - t0) * 1000
        return jsonify({
            "plaintext":       plaintext_bytes.decode(),
            "decrypt_time_ms": round(elapsed, 4),
        })
    except Exception as e:
        return jsonify({"error": f"ECC Decryption failed: {str(e)}"}), 400

@app.route("/api/ecc/ecdh", methods=["POST"])
def ecc_ecdh():
    req = request.json
    try:
        t0   = time.perf_counter()
        priv = serialization.load_pem_private_key(
            req["private_key_pem"].encode(), password=None, backend=default_backend()
        )
        peer_pub   = pub_from_pem(req["peer_public_key_pem"])
        shared_raw = priv.exchange(ec.ECDH(), peer_pub)
        elapsed    = (time.perf_counter() - t0) * 1000

        return jsonify({
            "shared_secret_b64": base64.b64encode(shared_raw).decode(),
            "elapsed_ms":        round(elapsed, 4)
        })
    except Exception as e:
        return jsonify({"error": f"ECDH failed: {str(e)}"}), 400

# ── RSA API Endpoints ────────────────────────────────────────────────────────
@app.route("/api/rsa/keygen", methods=["POST"])
def rsa_keygen():
    t0   = time.perf_counter()
    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    elapsed = (time.perf_counter() - t0) * 1000
    pub = priv.public_key()
    return jsonify({
        "private_key_pem": key_to_pem(priv),
        "public_key_pem":  pub_to_pem(pub),
        "gen_time_ms":     round(elapsed, 4),
    })

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    req = request.json
    pub = pub_from_pem(req["public_key_pem"])

    # Time only the core RSA public-key encryption operation
    t0 = time.perf_counter()
    ct = pub.encrypt(
        req["plaintext"].encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    elapsed = (time.perf_counter() - t0) * 1000

    return jsonify({
        "ciphertext_b64":  base64.b64encode(ct).decode(),
        "encrypt_time_ms": round(elapsed, 4),
    })

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    req = request.json
    try:
        t0   = time.perf_counter()
        priv = serialization.load_pem_private_key(
            req["private_key_pem"].encode(), password=None, backend=default_backend()
        )
        ct = base64.b64decode(req["ciphertext_b64"])
        pt = priv.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        elapsed = (time.perf_counter() - t0) * 1000
        return jsonify({"plaintext": pt.decode(), "decrypt_time_ms": round(elapsed, 4)})
    except Exception as e:
        return jsonify({"error": f"RSA Decryption failed: {str(e)}"}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)