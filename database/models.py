# ================================================================
# database/models.py  — CS3403 Network Security | RV University
#
# 4 TABLES:
#   users       → username, email, SHA256(password)
#   files       → metadata + RSA-encrypted AES key + SHA256 hash
#   file_access → access control rows (sharing info persists here)
#   audit_logs  → every action logged
#
# FIX: DB_PATH uses absolute path from this file so it ALWAYS
#      persists regardless of which directory you run from.
#      Shared files NEVER disappear after restart because they
#      are stored in file_access table — which is inside this DB.
# ================================================================

import sqlite3, os

# Absolute path — DB always found regardless of where you run from
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_transfer.db')

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")   # enforce FK constraints
    conn.execute("PRAGMA journal_mode = WAL")  # WAL mode = safer writes
    return conn

def init_db():
    conn = get_connection()
    cur  = conn.cursor()

    # USERS — password_hash is SHA256(password), NEVER plain text
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT UNIQUE NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # FILES — encrypted_aes_key = RSA(AES key), safe to store
    cur.execute('''CREATE TABLE IF NOT EXISTS files (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        original_filename TEXT NOT NULL,
        stored_filename   TEXT UNIQUE NOT NULL,
        file_size         INTEGER NOT NULL,
        mime_type         TEXT DEFAULT 'application/octet-stream',
        encrypted_aes_key TEXT NOT NULL,
        iv                TEXT NOT NULL,
        sha256_hash       TEXT NOT NULL,
        owner_id          INTEGER NOT NULL,
        uploaded_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    )''')

    # FILE_ACCESS — THIS IS WHERE SHARING PERSISTS ACROSS RESTARTS
    # Every share_file() call inserts one row here.
    # On restart: rows still exist → shared files still visible.
    cur.execute('''CREATE TABLE IF NOT EXISTS file_access (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id     INTEGER NOT NULL,
        user_id     INTEGER NOT NULL,
        permission  TEXT DEFAULT 'read',
        granted_by  INTEGER NOT NULL,
        granted_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(file_id, user_id),
        FOREIGN KEY (file_id)    REFERENCES files(id)  ON DELETE CASCADE,
        FOREIGN KEY (user_id)    REFERENCES users(id)  ON DELETE CASCADE,
        FOREIGN KEY (granted_by) REFERENCES users(id)
    )''')

    # AUDIT_LOGS — complete security trail
    cur.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        username   TEXT,
        action     TEXT NOT NULL,
        file_id    INTEGER,
        filename   TEXT,
        details    TEXT,
        ip_address TEXT,
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()
    print(f"[DB] Tables ready at: {DB_PATH}")
