# api.py — BarxeySolo Key Server
# Deploy on Railway.app for free
# railway init → railway up

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import sqlite3, os, secrets, string, hashlib, hmac

app = CORS(app)
DB   = "barxeysolo.db"
SECRET = os.environ.get("API_SECRET", "changeme123")  # set in Railway env vars

# ── DB SETUP ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key        TEXT PRIMARY KEY,
                hwid       TEXT,
                tier       TEXT DEFAULT 'Standard',
                created_at INTEGER,
                expires_at INTEGER,
                revoked    INTEGER DEFAULT 0,
                uses       INTEGER DEFAULT 0,
                note       TEXT
            )
        """)
        db.commit()

init_db()

# ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
def check_secret():
    return request.headers.get("X-Secret") == SECRET

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key  = str(data.get("key","")).upper().strip()
    hwid = str(data.get("hwid","")).upper().strip()

    if not key or not hwid:
        return jsonify(valid=False, message="Missing key or HWID.")

    with get_db() as db:
        row = db.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone()

    if not row:
        return jsonify(valid=False, message="Invalid key.")
    if row["revoked"]:
        return jsonify(valid=False, message="Key has been revoked.")
    if row["expires_at"] and row["expires_at"] < int(datetime.utcnow().timestamp()):
        return jsonify(valid=False, message="Key has expired.")

    # HWID lock
    if not row["hwid"]:
        # first use — bind to this HWID
        with get_db() as db:
            db.execute("UPDATE keys SET hwid=?, uses=uses+1 WHERE key=?", (hwid, key))
            db.commit()
    elif row["hwid"] != hwid:
        return jsonify(valid=False, message="Key is locked to a different machine.")
    else:
        with get_db() as db:
            db.execute("UPDATE keys SET uses=uses+1 WHERE key=?", (key,))
            db.commit()

    return jsonify(valid=True, message="OK", tier=row["tier"] or "Standard")

@app.route("/admin/gen", methods=["POST"])
def gen_key():
    if not check_secret():
        return jsonify(error="Unauthorized"), 403
    data  = request.get_json(silent=True) or {}
    tier  = data.get("tier", "Standard")
    note  = data.get("note", "")
    chars = string.ascii_uppercase + string.digits
    seg   = lambda: ''.join(secrets.choice(chars) for _ in range(4))
    key   = f"BARX-{seg()}-{seg()}-{seg()}"
    with get_db() as db:
        db.execute("INSERT INTO keys (key,tier,created_at,note) VALUES (?,?,?,?)",
                   (key, tier, int(datetime.utcnow().timestamp()), note))
        db.commit()
    return jsonify(key=key, tier=tier)

@app.route("/admin/keys", methods=["GET"])
def list_keys():
    if not check_secret():
        return jsonify(error="Unauthorized"), 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    return jsonify(keys=[dict(r) for r in rows])

@app.route("/admin/revoke", methods=["POST"])
def revoke():
    if not check_secret():
        return jsonify(error="Unauthorized"), 403
    key = (request.get_json(silent=True) or {}).get("key","").upper()
    with get_db() as db:
        db.execute("UPDATE keys SET revoked=1 WHERE key=?", (key,))
        db.commit()
    return jsonify(ok=True)

@app.route("/admin/reset_hwid", methods=["POST"])
def reset_hwid():
    if not check_secret():
        return jsonify(error="Unauthorized"), 403
    key = (request.get_json(silent=True) or {}).get("key","").upper()
    with get_db() as db:
        db.execute("UPDATE keys SET hwid=NULL WHERE key=?", (key,))
        db.commit()
    return jsonify(ok=True)

@app.route("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
