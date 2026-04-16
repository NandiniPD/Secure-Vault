# ================================================================
# run.py  — Main Flask Server
# CS3403 Network Security | RV University
#
# START:  python run.py
# OPEN:   http://localhost:5000
#
# ALL FIXES APPLIED:
#   ✅ Login failed message shows exact reason
#   ✅ Shared files persist after restart (DB + WAL mode)
#   ✅ Users list API for share modal
#   ✅ File validation (size + type)
#   ✅ Proper HTTP error codes everywhere
#   ✅ Access denied logged to audit trail
#   ✅ revoke_share endpoint added
# ================================================================

import os, sys, io, socket
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from functools import wraps

from database.models import init_db
from server.auth import (register_user, login_user, verify_jwt_token,
                         get_all_users, get_user_by_id)
from server.encryption import (load_rsa_keys, serialize_public_key,
                                benchmark_aes_vs_des)
from server.file_handler import (upload_file, download_file, get_user_files,
                                  share_file, revoke_share, delete_file,
                                  get_shared_by_me, tamper_file_hash)
from server.audit_log import (log_action, get_all_logs, get_user_logs,
                               get_security_alerts, get_user_security_alerts,
                               get_log_stats)

app = Flask(__name__, static_folder='client', static_url_path='')
CORS(app)

KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')
print("[SERVER] Loading RSA-2048 keys...")
PRIVATE_KEY, PUBLIC_KEY = load_rsa_keys(keys_dir=KEYS_DIR)
init_db()


# ── JWT DECORATOR ─────────────────────────────────────────────
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        h = request.headers.get('Authorization', '')
        if not h.startswith('Bearer '):
            return jsonify({"error": "Please login first"}), 401
        payload = verify_jwt_token(h.split(' ')[1])
        if not payload:
            return jsonify({"error": "Session expired. Please login again."}), 401
        request.user_id  = payload['user_id']
        request.username = payload['username']
        return f(*args, **kwargs)
    return decorated

def ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def get_lan_ip():
    """Return this machine's LAN IP so other laptops can connect."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan = s.getsockname()[0]
        s.close()
        return lan
    except Exception:
        return "127.0.0.1"

LAN_IP = get_lan_ip()


# ── PUBLIC ROUTES ─────────────────────────────────────────────

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/public-key')
def pub_key():
    return jsonify({"public_key": serialize_public_key(PUBLIC_KEY)})

@app.route('/api/register', methods=['POST'])
def register():
    d = request.get_json() or {}
    r = register_user(d.get('username',''), d.get('email',''), d.get('password',''))
    if r['success']:
        log_action(r['user_id'], d.get('username'), 'REGISTER', ip_address=ip())
        return jsonify({"message": "Account created! You can now login."}), 201
    # FIX: Return exact error message so UI can display it
    return jsonify({"error": r['error']}), 400

@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json() or {}
    username = d.get('username', '').strip()
    password = d.get('password', '')
    r = login_user(username, password)
    if r['success']:
        log_action(r['user_id'], r['username'], 'LOGIN', ip_address=ip())
        return jsonify({
            "token":    r['token'],
            "user_id":  r['user_id'],
            "username": r['username']
        })
    # FIX: Log failed attempt AND return specific error message.
    # If password was wrong for an existing account, login_user()
    # returns user_id + canonical username so we can tie this
    # LOGIN_FAILED row to that specific user for per-user alerts.
    log_action(
        r.get('user_id'),
        r.get('username') or (username or '?'),
        'LOGIN_FAILED',
        details=r['error'],
        ip_address=ip()
    )
    return jsonify({"error": r['error']}), 401


# ── FILE ROUTES ───────────────────────────────────────────────

@app.route('/api/files')
@jwt_required
def list_files():
    return jsonify({"files": get_user_files(request.user_id)})

@app.route('/api/files/upload', methods=['POST'])
@jwt_required
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file selected"}), 400
    f = request.files['file']
    if not f.filename or f.filename.strip() == '':
        return jsonify({"error": "Please select a file"}), 400

    r = upload_file(
        file_data         = f.read(),
        original_filename = f.filename,
        mime_type         = f.content_type or 'application/octet-stream',
        owner_id          = request.user_id,
        public_key        = PUBLIC_KEY,
        private_key       = PRIVATE_KEY
    )
    if r['success']:
        log_action(request.user_id, request.username, 'UPLOAD',
                   file_id=r['file_id'], filename=f.filename,
                   details=f"size:{r['size']}B sha256:{r['sha256'][:16]}...",
                   ip_address=ip())
        return jsonify(r), 201
    return jsonify({"error": r['error']}), 400

@app.route('/api/files/<int:fid>/download')
@jwt_required
def download(fid):
    r = download_file(fid, request.user_id, PRIVATE_KEY)
    if r['success']:
        log_action(request.user_id, request.username, 'DOWNLOAD',
                   file_id=fid, filename=r['filename'],
                   details=f"sha256_ok:{r['sha256_verified']}",
                   ip_address=ip())
        return send_file(
            io.BytesIO(r['data']),
            download_name = r['filename'],
            as_attachment = True,
            mimetype      = r['mime_type']
        )
    # FIX: Log ACCESS_DENIED and return proper message
    if 'denied' in r.get('error','').lower() or 'not been shared' in r.get('error','').lower():
        log_action(request.user_id, request.username, 'ACCESS_DENIED',
                   file_id=fid, details=r['error'], ip_address=ip())
        return jsonify({"error": r['error']}), 403
    # SHA-256 integrity failure → explicit 409 to show tampering
    if 'integrity check failed' in r.get('error','').lower():
        return jsonify({"error": r['error']}), 409
    return jsonify({"error": r['error']}), 404

@app.route('/api/files/<int:fid>/share', methods=['POST'])
@jwt_required
def share(fid):
    d = request.get_json() or {}
    target_id  = d.get('user_id')
    permission = d.get('permission', 'read')

    if not target_id:
        return jsonify({"error": "Please select a user to share with"}), 400

    r = share_file(fid, request.user_id, int(target_id), permission)
    if r['success']:
        log_action(request.user_id, request.username, 'SHARE',
                   file_id=fid,
                   details=f"shared_with_user_id:{target_id} perm:{permission}",
                   ip_address=ip())
        return jsonify(r)
    return jsonify({"error": r['error']}), 400

@app.route('/api/files/<int:fid>/revoke', methods=['POST'])
@jwt_required
def revoke(fid):
    d = request.get_json() or {}
    r = revoke_share(fid, request.user_id, d.get('user_id'))
    if r['success']:
        log_action(request.user_id, request.username, 'REVOKE_SHARE',
                   file_id=fid, ip_address=ip())
        return jsonify(r)
    return jsonify({"error": r['error']}), 400

@app.route('/api/files/<int:fid>', methods=['DELETE'])
@jwt_required
def delete(fid):
    r = delete_file(fid, request.user_id)
    if r['success']:
        log_action(request.user_id, request.username, 'DELETE',
                   file_id=fid, details=r['message'], ip_address=ip())
        return jsonify(r)
    return jsonify({"error": r['error']}), 403

@app.route('/api/files/shared-by-me')
@jwt_required
def shared_by_me():
    return jsonify({"shares": get_shared_by_me(request.user_id)})


@app.route('/api/files/<int:fid>/tamper-hash', methods=['POST'])
@jwt_required
def tamper_hash(fid):
    """
    DEMO ONLY: Intentionally corrupt the stored SHA-256 hash of a file
    you own, to demonstrate how integrity verification blocks tampered
    data on download.
    """
    r = tamper_file_hash(fid, request.user_id)
    if r['success']:
        log_action(request.user_id, request.username, 'INTEGRITY_TAMPER_DEMO',
                   file_id=fid, details="SHA-256 hash flipped for demo",
                   ip_address=ip())
        return jsonify(r)
    return jsonify({"error": r['error']}), 400


# ── USER ROUTES ───────────────────────────────────────────────

@app.route('/api/users')
@jwt_required
def users():
    """
    FIX: Returns all registered users except current user.
    This is what populates the share modal dropdown.
    If empty → no other users registered yet.
    """
    all_users = get_all_users(exclude_user_id=request.user_id)
    return jsonify({
        "users": all_users,
        "count": len(all_users)
    })

@app.route('/api/users/me')
@jwt_required
def me():
    return jsonify(get_user_by_id(request.user_id))


# ── LOG & STATS ROUTES ────────────────────────────────────────

@app.route('/api/logs')
@jwt_required
def all_logs():
    # Each user sees only their own audit log entries
    return jsonify({"logs": get_user_logs(request.user_id, 200)})

@app.route('/api/logs/alerts')
@jwt_required
def alerts():
    # Each user sees only their own LOGIN_FAILED / ACCESS_DENIED events
    # (rows where audit_logs.user_id = current JWT user_id).
    return jsonify({"alerts": get_user_security_alerts(request.user_id)})

@app.route('/api/logs/stats')
@jwt_required
def stats():
    # Stats are scoped to the current user's own actions
    return jsonify(get_log_stats(user_id=request.user_id))

@app.route('/api/crypto/benchmark')
@jwt_required
def bench():
    return jsonify(benchmark_aes_vs_des(data_size_kb=100))

@app.route('/api/server-info')
@jwt_required
def server_info():
    """Returns the server's LAN IP so other devices know where to connect."""
    return jsonify({"lan_ip": LAN_IP, "port": 5000, "url": f"http://{LAN_IP}:5000"})


# ── STARTUP ───────────────────────────────────────────────────
if __name__ == '__main__':
    lan = get_lan_ip()
    print("\n" + "="*60)
    print("  SecureVault | CS3403 Network Security | RVU")
    print(f"  Local  -> http://localhost:5000")
    print(f"  Network -> http://{lan}:5000  (Share this URL with others)")
    print("  Crypto: AES-256 + RSA-2048 + SHA-256 + JWT")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
