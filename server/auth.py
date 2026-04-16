# ================================================================
# server/auth.py  — CS3403 Network Security | RV University
#
# HANDLES: Registration, Login, JWT tokens, password hashing
#
# ALGORITHMS:
#   SHA-256  → hash_password()   — stores SHA256(password) in DB
#   JWT HS256 → generate_jwt_token() — signed token after login
# ================================================================

import hashlib, jwt, datetime, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from database.models import get_connection

JWT_SECRET    = os.environ.get("JWT_SECRET", "CS3403_SecureVault_RVU_2025!")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_H  = 24

# ── PASSWORD HASHING ──────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed

# ── JWT ───────────────────────────────────────────────────────
def generate_jwt_token(user_id: int, username: str) -> str:
    payload = {
        "user_id":  user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_H),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ── REGISTER ──────────────────────────────────────────────────
def register_user(username: str, email: str, password: str) -> dict:
    username = username.strip()
    email    = email.strip().lower()

    if not username:
        return {"success": False, "error": "Username cannot be empty"}
    if not email or '@' not in email:
        return {"success": False, "error": "Please enter a valid email address"}
    if len(password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}

    conn = get_connection()
    cur  = conn.cursor()
    # Prevent duplicate accounts differing only by letter case.
    cur.execute(
        "SELECT id FROM users WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)",
        (username, email)
    )
    if cur.fetchone():
        conn.close()
        return {"success": False, "error": "Username or email already registered"}
    cur.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
        (username, email, hash_password(password))
    )
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return {"success": True, "user_id": uid, "username": username}

# ── LOGIN ─────────────────────────────────────────────────────
def login_user(username: str, password: str) -> dict:
    username = username.strip()

    if not username or not password:
        return {"success": False, "error": "Username and password are required"}

    conn = get_connection()
    cur  = conn.cursor()
    # Accept username OR email and compare case-insensitively.
    cur.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE LOWER(username)=LOWER(?) OR LOWER(email)=LOWER(?)
        """,
        (username, username)
    )
    user = cur.fetchone()
    conn.close()

    # FIX: Give specific error messages for better UX
    if not user:
        return {
            "success": False,
            "error": f"No account found with username '{username}'. Please register first."
        }

    # If password is wrong, still return the resolved user so we can
    # tie LOGIN_FAILED events to the correct user_id for per-user alerts.
    if not verify_password(password, user["password_hash"]):
        return {
            "success":  False,
            "error":    "Incorrect password. Please try again.",
            "user_id":  user["id"],
            "username": user["username"],
        }

    token = generate_jwt_token(user["id"], user["username"])
    return {
        "success":  True,
        "token":    token,
        "user_id":  user["id"],
        "username": user["username"]
    }

# ── HELPERS ───────────────────────────────────────────────────
def get_all_users(exclude_user_id=None):
    conn = get_connection()
    cur  = conn.cursor()
    if exclude_user_id:
        cur.execute(
            "SELECT id, username, email FROM users WHERE id != ? ORDER BY username",
            (exclude_user_id,)
        )
    else:
        cur.execute("SELECT id, username, email FROM users ORDER BY username")
    users = [dict(r) for r in cur.fetchall()]
    conn.close()
    return users

def get_user_by_id(user_id: int):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, username, email, created_at FROM users WHERE id=?",
        (user_id,)
    )
    user = cur.fetchone()
    conn.close()
    return dict(user) if user else None
