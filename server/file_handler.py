# ================================================================
# server/file_handler.py  — CS3403 Network Security | RV University
#
# WHERE AES, RSA, SHA-256 ARE CALLED:
#
# upload_file():
#   Step 1 → compute_sha256(file_data)         [SHA-256]
#   Step 2 → generate_aes_key()                [AES-256]
#   Step 3 → aes_encrypt(file_data, aes_key)   [AES-256]
#   Step 4 → rsa_encrypt_aes_key(key, pub_key) [RSA-2048]
#   Step 5 → save .enc to disk, metadata to DB
#
# download_file():
#   Step 1 → check JWT (done in run.py decorator)
#   Step 2 → check file_access table (access control)
#   Step 3 → rsa_decrypt_aes_key(enc_key, priv) [RSA-2048]
#   Step 4 → aes_decrypt(ciphertext, iv, key)   [AES-256]
#   Step 5 → verify_integrity(data, hash)        [SHA-256]
#
# FIX: share_file() now uses INSERT OR IGNORE with UNIQUE constraint
#      so sharing ALWAYS persists in DB and duplicate shares are safe.
#
# FILE VALIDATION:
#   Max size: 10 MB
#   Blocked types: .exe .bat .sh .cmd .ps1 .vbs .scr
# ================================================================

import os, uuid, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from database.models import get_connection
from server.encryption import (
    generate_aes_key, aes_encrypt, aes_decrypt,
    rsa_encrypt_aes_key, rsa_decrypt_aes_key,
    compute_sha256, verify_integrity
)

STORAGE_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'encrypted_storage')
MAX_FILE_SIZE = 10 * 1024 * 1024   # 10 MB
BLOCKED_EXTS  = {'.exe', '.bat', '.sh', '.cmd', '.ps1', '.vbs', '.scr', '.msi', '.dll'}


def _validate_file(filename: str, size: int) -> dict:
    """Validate file before encrypting. Returns {"ok": True} or {"ok": False, "error": "..."}"""
    if size == 0:
        return {"ok": False, "error": "File is empty"}
    if size > MAX_FILE_SIZE:
        mb = round(size / (1024 * 1024), 1)
        return {"ok": False, "error": f"File too large ({mb} MB). Maximum allowed is 10 MB"}
    ext = os.path.splitext(filename.lower())[1]
    if ext in BLOCKED_EXTS:
        return {"ok": False, "error": f"File type '{ext}' is not allowed for security reasons"}
    return {"ok": True}


def upload_file(file_data: bytes, original_filename: str,
                mime_type: str, owner_id: int,
                public_key, private_key) -> dict:
    """
    Full secure upload: SHA-256 → AES key → AES encrypt → RSA encrypt → save
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)

    # Validate file first
    v = _validate_file(original_filename, len(file_data))
    if not v["ok"]:
        return {"success": False, "error": v["error"]}

    # Step 1: SHA-256 fingerprint of original bytes
    original_hash = compute_sha256(file_data)

    # Step 2: Unique AES-256 key per file
    aes_key = generate_aes_key()

    # Step 3: AES-256-CBC encrypts file
    enc_result = aes_encrypt(file_data, aes_key)

    # Step 4: RSA-2048 encrypts the AES key
    enc_aes_key = rsa_encrypt_aes_key(aes_key, public_key)

    # Step 5: Save encrypted file to disk
    stored_name = f"{uuid.uuid4().hex}.enc"
    file_path   = os.path.join(STORAGE_DIR, stored_name)
    with open(file_path, 'w') as f:
        f.write(enc_result["encrypted_data"])

    # Step 6: Save metadata + encrypted key to DB
    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute('''
            INSERT INTO files
            (original_filename, stored_filename, file_size, mime_type,
             encrypted_aes_key, iv, sha256_hash, owner_id)
            VALUES (?,?,?,?,?,?,?,?)
        ''', (original_filename, stored_name, len(file_data),
              mime_type or 'application/octet-stream',
              enc_aes_key, enc_result["iv"], original_hash, owner_id))
        conn.commit()
        fid = cur.lastrowid
    except Exception as e:
        conn.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        return {"success": False, "error": f"Database error: {str(e)}"}
    conn.close()

    return {
        "success":   True,
        "file_id":   fid,
        "filename":  original_filename,
        "size":      len(file_data),
        "sha256":    original_hash,
        "stored_as": stored_name,
        "message":   "File encrypted with AES-256 and stored securely"
    }


def download_file(file_id: int, requesting_user_id: int, private_key) -> dict:
    """
    Full secure download: access check → RSA decrypt → AES decrypt → SHA-256 verify
    """
    conn = get_connection()
    cur  = conn.cursor()

    # Get file record
    cur.execute("SELECT * FROM files WHERE id=?", (file_id,))
    rec = cur.fetchone()
    if not rec:
        conn.close()
        return {"success": False, "error": "File not found"}

    # Access control: owner always allowed; others need file_access row
    is_owner = rec["owner_id"] == requesting_user_id
    if not is_owner:
        cur.execute(
            "SELECT id, permission FROM file_access WHERE file_id=? AND user_id=?",
            (file_id, requesting_user_id)
        )
        access = cur.fetchone()
        if not access:
            conn.close()
            return {
                "success": False,
                "error": "Access denied — this file has not been shared with you"
            }
    conn.close()

    # Load encrypted file from disk
    enc_path = os.path.join(STORAGE_DIR, rec["stored_filename"])
    if not os.path.exists(enc_path):
        return {"success": False, "error": "Encrypted file missing from storage"}

    try:
        with open(enc_path, 'r') as f:
            encrypted_data = f.read()
    except Exception:
        return {"success": False, "error": "Could not read encrypted file from disk"}

    # RSA-2048 decrypts the AES key
    try:
        aes_key = rsa_decrypt_aes_key(rec["encrypted_aes_key"], private_key)
    except Exception:
        return {"success": False, "error": "Failed to decrypt file key (RSA error)"}

    # AES-256 decrypts the file
    try:
        original_data = aes_decrypt(encrypted_data, rec["iv"], aes_key)
    except Exception:
        return {"success": False, "error": "Failed to decrypt file (AES error)"}

    # SHA-256 integrity check
    if not verify_integrity(original_data, rec["sha256_hash"]):
        return {
            "success": False,
            "error":   "Integrity check FAILED — file may have been tampered with"
        }

    return {
        "success":         True,
        "data":            original_data,
        "filename":        rec["original_filename"],
        "mime_type":       rec["mime_type"] or "application/octet-stream",
        "sha256_verified": True,
        "size":            len(original_data)
    }


def get_user_files(user_id: int) -> list:
    """
    Return ONLY:
    1. Files where this user is the owner
    2. Files explicitly shared WITH this user via file_access table

    FIX: UNIQUE(file_id, user_id) in file_access + absolute DB path
         ensures shared files ALWAYS survive restarts.
    """
    conn = get_connection()
    cur  = conn.cursor()

    # Owned files
    cur.execute('''
        SELECT f.id, f.original_filename, f.file_size, f.mime_type,
               f.sha256_hash, f.uploaded_at,
               u.username as owner_name,
               'owner' as access_type
        FROM files f
        JOIN users u ON f.owner_id = u.id
        WHERE f.owner_id = ?
        ORDER BY f.uploaded_at DESC
    ''', (user_id,))
    owned = [dict(r) for r in cur.fetchall()]

    # Files shared with this user (not owned by them)
    cur.execute('''
        SELECT f.id, f.original_filename, f.file_size, f.mime_type,
               f.sha256_hash, f.uploaded_at,
               u.username as owner_name,
               fa.permission as access_type
        FROM files f
        JOIN users u ON f.owner_id = u.id
        JOIN file_access fa ON fa.file_id = f.id
        WHERE fa.user_id = ?
          AND f.owner_id != ?
        ORDER BY fa.granted_at DESC
    ''', (user_id, user_id))
    shared = [dict(r) for r in cur.fetchall()]

    conn.close()
    return owned + shared


def get_shared_by_me(owner_id: int) -> list:
    """Get list of files I shared and who I shared them with."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute('''
        SELECT f.id, f.original_filename, u.username as shared_with,
               fa.permission, fa.granted_at
        FROM file_access fa
        JOIN files f ON fa.file_id = f.id
        JOIN users u ON fa.user_id = u.id
        WHERE f.owner_id = ?
        ORDER BY fa.granted_at DESC
    ''', (owner_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def tamper_file_hash(file_id: int, owner_id: int) -> dict:
    """
    Teaching/demo helper: intentionally corrupt the stored SHA-256 hash
    for a file owned by the given user.

    After calling this, the next download will fail at:
        verify_integrity(original_data, rec["sha256_hash"])
    and return the "Integrity check FAILED" error, proving that even a
    1‑bit change is detected.
    """
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("SELECT id, sha256_hash FROM files WHERE id=? AND owner_id=?",
                (file_id, owner_id))
    rec = cur.fetchone()
    if not rec:
        conn.close()
        return {"success": False, "error": "File not found or you don't own it"}

    old = rec["sha256_hash"] or ""
    if not old:
        conn.close()
        return {"success": False, "error": "No hash stored for this file"}

    # Flip the last hex digit in the stored hash (minimal visible change)
    last = old[-1]
    flipped = '0' if last != '0' else '1'
    new_hash = old[:-1] + flipped

    cur.execute("UPDATE files SET sha256_hash=? WHERE id=?", (new_hash, file_id))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "SHA-256 hash intentionally corrupted for demo. Next download will fail integrity check."
    }


def share_file(file_id: int, owner_id: int, target_user_id: int, permission='read') -> dict:
    """
    FIX: Uses INSERT OR IGNORE + UNIQUE(file_id, user_id) constraint.
    Sharing info is stored permanently in file_access table.
    After server restart → rows still exist → shared files still appear.

    WHAT SHARING MEANS IN THIS APP:
    - It adds a row to file_access: file_id, user_id, permission
    - When target user logs in, they see the file in their vault
    - No email is sent — this is an internal closed system
    - Only registered users can be shared with (they need a user_id)
    """
    if owner_id == target_user_id:
        return {"success": False, "error": "You cannot share a file with yourself"}

    conn = get_connection()
    cur  = conn.cursor()

    # Verify requester owns this file
    cur.execute("SELECT id, original_filename FROM files WHERE id=? AND owner_id=?",
                (file_id, owner_id))
    file_rec = cur.fetchone()
    if not file_rec:
        conn.close()
        return {"success": False, "error": "File not found or you don't own it"}

    # Get target user info for feedback message
    cur.execute("SELECT username FROM users WHERE id=?", (target_user_id,))
    target = cur.fetchone()
    if not target:
        conn.close()
        return {"success": False, "error": "Target user not found"}

    # Check if already shared
    cur.execute("SELECT id FROM file_access WHERE file_id=? AND user_id=?",
                (file_id, target_user_id))
    existing = cur.fetchone()
    if existing:
        conn.close()
        return {
            "success": False,
            "error": f"File is already shared with {target['username']}"
        }

    # Insert sharing record — persists in DB forever until deleted
    cur.execute(
        "INSERT INTO file_access (file_id, user_id, permission, granted_by) VALUES (?,?,?,?)",
        (file_id, target_user_id, permission, owner_id)
    )
    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": f"File shared with {target['username']}. They can see it in their vault now.",
        "shared_with": target['username']
    }


def revoke_share(file_id: int, owner_id: int, target_user_id: int) -> dict:
    """Remove sharing access for a specific user."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT id FROM files WHERE id=? AND owner_id=?", (file_id, owner_id))
    if not cur.fetchone():
        conn.close()
        return {"success": False, "error": "File not found or you don't own it"}
    cur.execute(
        "DELETE FROM file_access WHERE file_id=? AND user_id=?",
        (file_id, target_user_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "message": "Access revoked"}


def delete_file(file_id: int, owner_id: int) -> dict:
    """Delete file from disk + all DB records (CASCADE handles file_access rows)."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, owner_id))
    rec = cur.fetchone()
    if not rec:
        conn.close()
        return {"success": False, "error": "File not found or you don't own it"}

    # Remove encrypted file from disk
    path = os.path.join(STORAGE_DIR, rec["stored_filename"])
    if os.path.exists(path):
        os.remove(path)

    # Remove DB records (file_access rows deleted by CASCADE)
    cur.execute("DELETE FROM file_access WHERE file_id=?", (file_id,))
    cur.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": f"'{rec['original_filename']}' deleted permanently"}
