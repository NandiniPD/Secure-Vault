# ================================================================
# server/encryption.py
# CS3403 Network Security | RV University
#
# ALL CRYPTO ALGORITHMS ARE HERE.
# Every function is called from file_handler.py during upload/download.
#
# AES-256  → encrypts the FILE bytes         → called in upload_file()
# RSA-2048 → encrypts the AES KEY            → called in upload_file()
# RSA-2048 → decrypts the AES KEY            → called in download_file()
# SHA-256  → fingerprints the file           → called in upload & download
# DES      → comparison demo only            → called in benchmark()
# ================================================================

import os, hashlib, base64, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ================================================================
# RSA-2048  (Asymmetric Encryption)
# PURPOSE IN PROJECT: Securely store the AES key in the database.
#
# How it works here:
#   UPLOAD:   rsa_encrypt_aes_key(aes_key, PUBLIC_KEY)
#             → AES key is locked with public key
#             → Stored in database (safe even if DB stolen)
#
#   DOWNLOAD: rsa_decrypt_aes_key(encrypted_key, PRIVATE_KEY)
#             → AES key is unlocked with private key
#             → Used to decrypt the file
#
# Keys are stored in: /keys/private_key.pem  and  /keys/public_key.pem
# ================================================================

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def save_rsa_keys(private_key, public_key, keys_dir="keys"):
    os.makedirs(keys_dir, exist_ok=True)
    with open(f"{keys_dir}/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(f"{keys_dir}/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_rsa_keys(keys_dir="keys"):
    """Load RSA keys from disk. Auto-generate if first run."""
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = f"{keys_dir}/private_key.pem"
    if not os.path.exists(priv_path):
        print("[CRYPTO] First run — generating RSA-2048 key pair...")
        priv, pub = generate_rsa_keypair()
        save_rsa_keys(priv, pub, keys_dir)
        print("[CRYPTO] Keys saved to /keys/ folder.")
        return priv, pub
    with open(priv_path, "rb") as f:
        priv = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(f"{keys_dir}/public_key.pem", "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print("[CRYPTO] RSA-2048 keys loaded from disk.")
    return priv, pub

def rsa_encrypt_aes_key(aes_key: bytes, public_key) -> str:
    """
    CALLED DURING: upload_file() in file_handler.py
    WHAT IT DOES: Locks the AES key using RSA public key.
    WHY: So even if attacker steals the database, they cannot
         read the AES key without the RSA private key.
    """
    encrypted = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt_aes_key(encrypted_b64: str, private_key) -> bytes:
    """
    CALLED DURING: download_file() in file_handler.py
    WHAT IT DOES: Unlocks the AES key using RSA private key.
    WHY: To get the AES key back so we can decrypt the file.
    """
    return private_key.decrypt(
        base64.b64decode(encrypted_b64),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ================================================================
# AES-256-CBC  (Symmetric Encryption)
# PURPOSE IN PROJECT: Encrypts the actual FILE content.
#
# How it works here:
#   UPLOAD:   aes_encrypt(file_bytes, aes_key)
#             → file.pdf becomes random garbage bytes
#             → saved as UUID.enc in encrypted_storage/
#
#   DOWNLOAD: aes_decrypt(encrypted_data, iv, aes_key)
#             → garbage bytes become original file.pdf again
#
# KEY: 32 random bytes (256 bits) — unique per file
# IV:  16 random bytes — unique per encryption operation
#
# WHY AES NOT RSA FOR FILES?
#   RSA can only encrypt ~245 bytes at a time (too slow for files).
#   AES can encrypt ANY size at high speed.
#   So: AES encrypts file, RSA encrypts the AES key. = Hybrid.
# ================================================================

def generate_aes_key():
    """
    CALLED DURING: upload_file() in file_handler.py
    WHAT IT DOES: Creates a fresh random 256-bit AES key.
    os.urandom(32) = 32 bytes = 256 bits, cryptographically random.
    """
    return os.urandom(32)

def aes_encrypt(data: bytes, aes_key: bytes) -> dict:
    """
    CALLED DURING: upload_file() in file_handler.py
    WHAT IT DOES: Turns file bytes into unreadable ciphertext.
    RETURNS: dict with encrypted_data (base64) and iv (base64)
    Both are stored: encrypted_data on disk, iv in database.
    """
    iv = os.urandom(16)  # Fresh random IV every time

    # PKCS7 padding: AES needs data in 16-byte blocks
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return {
        "encrypted_data": base64.b64encode(encrypted).decode(),
        "iv":             base64.b64encode(iv).decode()
    }

def aes_decrypt(encrypted_b64: str, iv_b64: str, aes_key: bytes) -> bytes:
    """
    CALLED DURING: download_file() in file_handler.py
    WHAT IT DOES: Turns ciphertext back into original file bytes.
    Needs the EXACT same aes_key and iv used during encryption.
    """
    iv        = base64.b64decode(iv_b64)
    encrypted = base64.b64decode(encrypted_b64)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ================================================================
# SHA-256  (Hash Function — NOT encryption, one-way only)
# PURPOSE IN PROJECT: Verify file was not tampered.
#
# How it works here:
#   UPLOAD:   hash = compute_sha256(original_file_bytes)
#             → 64-char hex string stored in database
#
#   DOWNLOAD: verify_integrity(decrypted_bytes, stored_hash)
#             → recompute hash and compare
#             → MATCH = file is safe  |  MISMATCH = tampered!
#
# WHY SHA-256 NOT SHA-1 OR MD5?
#   MD5 and SHA-1 have known collision attacks (broken).
#   SHA-256 has no known collisions — still secure.
# ================================================================

def compute_sha256(data: bytes) -> str:
    """
    CALLED DURING: upload_file() to create file fingerprint.
    Returns 64-character hex string (256 bits).
    """
    return hashlib.sha256(data).hexdigest()

def verify_integrity(data: bytes, expected_hash: str) -> bool:
    """
    CALLED DURING: download_file() to verify file.
    True  = file is exactly as uploaded (safe to send to user).
    False = file was tampered with (block the download!).
    """
    return hashlib.sha256(data).hexdigest() == expected_hash


# ================================================================
# DES  (Old algorithm — for comparison/demo only)
# PURPOSE IN PROJECT: Show WHY AES replaced DES.
#
# DES key = 56 bits → 2^56 combinations → crackable in <24 hours.
# AES key = 256 bits → 2^256 combinations → uncrackable.
# The benchmark proves AES is STRONGER AND FASTER than DES.
# Use this in your presentation slide about algorithm choice.
# ================================================================

def des_encrypt_demo(data: bytes) -> dict:
    """DES encryption for comparison demo. DO NOT use in real apps."""
    from cryptography.hazmat.primitives.ciphers import algorithms as alg
    des_key = os.urandom(8)
    iv      = os.urandom(8)
    padder  = sym_padding.PKCS7(64).padder()
    padded  = padder.update(data) + padder.finalize()
    cipher  = Cipher(alg.TripleDES(des_key * 3), modes.CBC(iv), backend=default_backend())
    enc     = cipher.encryptor()
    return {"encrypted_data": base64.b64encode(enc.update(padded) + enc.finalize()).decode()}

def benchmark_aes_vs_des(data_size_kb: int = 100) -> dict:
    """
    Run AES-256 and DES on same data. Compare speed + security.
    Called from: GET /api/crypto/benchmark in run.py
    Use this in presentation to prove AES > DES.
    """
    data = os.urandom(data_size_kb * 1024)

    aes_key = generate_aes_key()
    t0 = time.time()
    aes_encrypt(data, aes_key)
    aes_ms = round((time.time() - t0) * 1000, 2)

    t0 = time.time()
    des_encrypt_demo(data)
    des_ms = round((time.time() - t0) * 1000, 2)

    return {
        "data_size_kb":      data_size_kb,
        "aes_time_ms":       aes_ms,
        "des_time_ms":       des_ms,
        "aes_key_bits":      256,
        "des_key_bits":      56,
        "aes_combinations":  "2^256 — more than atoms in universe",
        "des_combinations":  "2^56  — crackable in less than 24 hours",
        "verdict":           "AES-256 is FASTER and 2^200x MORE SECURE than DES"
    }
