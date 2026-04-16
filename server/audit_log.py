# ================================================================
# server/audit_log.py
# CS3403 Network Security | RV University
#
# Logs every security event to the audit_logs table.
# This is how enterprise tools like Splunk and IBM QRadar work.
# Every UPLOAD, DOWNLOAD, SHARE, DELETE, LOGIN, LOGIN_FAILED
# gets a row in the database with timestamp + IP address.
# ================================================================

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from database.models import get_connection

def log_action(user_id, username, action,
               file_id=None, filename=None, details=None, ip_address=None):
    conn = get_connection()
    conn.cursor().execute(
        '''INSERT INTO audit_logs
           (user_id, username, action, file_id, filename, details, ip_address)
           VALUES (?,?,?,?,?,?,?)''',
        (user_id, username, action, file_id, filename, details, ip_address)
    )
    conn.commit()
    conn.close()

def get_all_logs(limit=200):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return logs

def get_user_logs(user_id, limit=200):
    """Return only the audit log entries that belong to the given user."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
        (user_id, limit)
    )
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return logs

def get_security_alerts(limit=100):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute('''SELECT * FROM audit_logs
                   WHERE action IN ('LOGIN_FAILED','ACCESS_DENIED')
                   ORDER BY timestamp DESC LIMIT ?''', (limit,))
    alerts = [dict(r) for r in cur.fetchall()]
    conn.close()
    return alerts

def get_user_security_alerts(user_id, limit=100):
    """Return LOGIN_FAILED / ACCESS_DENIED events for the given user only."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute('''SELECT * FROM audit_logs
                   WHERE action IN ('LOGIN_FAILED','ACCESS_DENIED')
                     AND user_id=?
                   ORDER BY timestamp DESC LIMIT ?''', (user_id, limit))
    alerts = [dict(r) for r in cur.fetchall()]
    conn.close()
    return alerts

def get_log_stats(user_id=None):
    """Return action counts. If user_id is given, counts are scoped to that user."""
    conn = get_connection()
    cur  = conn.cursor()
    stats = {}
    for a in ['UPLOAD','DOWNLOAD','SHARE','DELETE','LOGIN',
              'LOGIN_FAILED','ACCESS_DENIED','REGISTER']:
        if user_id is not None:
            cur.execute("SELECT COUNT(*) as c FROM audit_logs WHERE action=? AND user_id=?", (a, user_id))
        else:
            cur.execute("SELECT COUNT(*) as c FROM audit_logs WHERE action=?", (a,))
        stats[a] = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM users")
    stats['TOTAL_USERS'] = cur.fetchone()["c"]
    if user_id is not None:
        cur.execute("SELECT COUNT(*) as c FROM files WHERE owner_id=?", (user_id,))
    else:
        cur.execute("SELECT COUNT(*) as c FROM files")
    stats['TOTAL_FILES'] = cur.fetchone()["c"]
    conn.close()
    return stats
