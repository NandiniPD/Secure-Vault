# ================================================================
# tests/test_all.py
# CS3403 Network Security | RV University
# Run: python tests/test_all.py
#
# Tests every security module. Show this output in Review 3.
# ================================================================

import sys, os, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from server.encryption import *
from server.auth import hash_password, verify_password, generate_jwt_token, verify_jwt_token

passed = failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        print(f"  ✅  PASS  {name}")
        passed += 1
    else:
        print(f"  ❌  FAIL  {name}")
        failed += 1

print("\n" + "="*60)
print("  SecureVault — Full Security Test Suite")
print("  CS3403 Network Security | RV University")
print("="*60)

# ── AES-256 ───────────────────────────────────────────────────
print("\n[1] AES-256 Tests")
key  = generate_aes_key()
data = b"Confidential exam paper - AES-256 encryption test"
enc  = aes_encrypt(data, key)
dec  = aes_decrypt(enc['encrypted_data'], enc['iv'], key)

test("AES key is 256-bit (32 bytes)",        len(key) == 32)
test("AES IV is 128-bit (16 bytes)",          len(base64.b64decode(enc['iv'])) == 16)
test("AES encrypt → decrypt → same data",    dec == data)
test("Ciphertext is different from plaintext", enc['encrypted_data'] != data.decode())
test("Different files get different keys",    generate_aes_key() != generate_aes_key())
enc2 = aes_encrypt(data, key)
test("Same key + same data → different IV each time", enc['iv'] != enc2['iv'])

# ── RSA-2048 ──────────────────────────────────────────────────
print("\n[2] RSA-2048 Tests")
priv, pub = generate_rsa_keypair()
enc_key   = rsa_encrypt_aes_key(key, pub)
rec_key   = rsa_decrypt_aes_key(enc_key, priv)

test("RSA encrypt AES key → decrypt → same key",   key == rec_key)
test("RSA encrypted key ≠ original key",            enc_key.encode() != key)
priv2, pub2 = generate_rsa_keypair()
try:
    rsa_decrypt_aes_key(enc_key, priv2)
    test("Wrong private key cannot decrypt",        False)
except Exception:
    test("Wrong private key cannot decrypt",        True)

# ── SHA-256 ───────────────────────────────────────────────────
print("\n[3] SHA-256 Integrity Tests")
h = compute_sha256(data)
test("SHA-256 produces 64-char hex",               len(h) == 64)
test("Same data → same hash always",               compute_sha256(data) == h)
test("Integrity check passes for original data",   verify_integrity(data, h))
test("Integrity check fails for tampered data",    not verify_integrity(b"tampered!", h))
test("1 byte change → completely different hash",  compute_sha256(data) != compute_sha256(data+b'x'))

# ── JWT ───────────────────────────────────────────────────────
print("\n[4] JWT Authentication Tests")
token   = generate_jwt_token(1, "alice")
payload = verify_jwt_token(token)
test("JWT generated and verified",             payload is not None)
test("JWT payload has correct user_id",        payload.get('user_id') == 1)
test("JWT payload has correct username",       payload.get('username') == 'alice')
test("Tampered token is rejected",             verify_jwt_token(token[:-8]+"XXXXXXXX") is None)

# ── Password Hashing ──────────────────────────────────────────
print("\n[5] Password Hashing Tests")
h1 = hash_password("testpassword")
test("SHA-256 hash is 64 chars",               len(h1) == 64)
test("Correct password verified",             verify_password("testpassword", h1))
test("Wrong password rejected",               not verify_password("wrong", h1))
test("Plain ≠ hashed",                        h1 != "testpassword")

# ── Full Hybrid Encryption (End-to-End) ───────────────────────
print("\n[6] Full Upload→Download Flow (Hybrid Encryption)")
file_content = b"This simulates a real file upload and download." * 100
orig_hash    = compute_sha256(file_content)

# UPLOAD side
aes_k   = generate_aes_key()
enc_f   = aes_encrypt(file_content, aes_k)
enc_k   = rsa_encrypt_aes_key(aes_k, pub)

# DOWNLOAD side
rec_aes = rsa_decrypt_aes_key(enc_k, priv)
dec_f   = aes_decrypt(enc_f['encrypted_data'], enc_f['iv'], rec_aes)

test("Full upload→download: file bytes match", dec_f == file_content)
test("SHA-256 integrity verified after flow",  verify_integrity(dec_f, orig_hash))

# ── Summary ───────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  Results: {passed} passed  |  {failed} failed")
print(f"  {'✅  ALL TESTS PASSED' if failed == 0 else '❌  SOME TESTS FAILED'}")
print(f"{'='*60}\n")
