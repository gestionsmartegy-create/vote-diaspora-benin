import os
import sqlite3
import re
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioRestException

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
TWILIO_SID   = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM  = os.getenv("TWILIO_PHONE_NUMBER", "")
ADMIN_PWD    = os.getenv("ADMIN_PASSWORD", "admin2026")
DB_PATH      = os.path.join(os.path.dirname(__file__), "votes.db")

twilio = TwilioClient(TWILIO_SID, TWILIO_TOKEN) if TWILIO_SID else None

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rsvps (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name   TEXT NOT NULL,
                phone       TEXT NOT NULL UNIQUE,
                email       TEXT,
                city        TEXT NOT NULL,
                province    TEXT NOT NULL,
                confirmed   INTEGER DEFAULT 1,
                sms_sent    INTEGER DEFAULT 0,
                created_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS sms_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                phone       TEXT NOT NULL,
                message     TEXT NOT NULL,
                status      TEXT,
                twilio_sid  TEXT,
                sent_at     TEXT DEFAULT (datetime('now'))
            );
        """)

# ── App Setup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print(f"\n🗳️  Serveur élections démarré")
    print(f"📊 Admin: http://localhost:8001/admin.html")
    print(f"🔑 Password admin: {ADMIN_PWD}\n")
    yield

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files
app.mount("/static", StaticFiles(directory="public"), name="static")

# ── Schemas ───────────────────────────────────────────────────────────────────
class RSVPCreate(BaseModel):
    full_name: str
    phone: str
    email: Optional[str] = None
    city: str
    province: str

class BlastRequest(BaseModel):
    message: str
    province: Optional[str] = None
    limit: Optional[int] = None          # max contacts to send to
    voter_ids: Optional[list[int]] = None  # specific IDs to target

class SMSSingle(BaseModel):
    phone: str
    message: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def normalize_phone(phone: str) -> str:
    return re.sub(r"[\s\-().]", "", phone)

def require_admin(x_admin_token: str = Header(default="")):
    pass  # Auth désactivée pour présentation

def send_sms(to: str, body: str) -> dict:
    if not twilio or not TWILIO_FROM:
        print(f"[SMS MOCK] To: {to}\n{body}\n")
        return {"sid": "MOCK_SID"}
    msg = twilio.messages.create(body=body, from_=TWILIO_FROM, to=to)
    return {"sid": msg.sid}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return FileResponse("public/index.html")

@app.get("/admin.html")
async def admin_page():
    return FileResponse("public/admin.html")

# POST /api/rsvp
@app.post("/api/rsvp")
@limiter.limit("10/minute")
async def rsvp(request: Request, data: RSVPCreate):
    if not data.full_name or not data.phone or not data.city or not data.province:
        raise HTTPException(status_code=400, detail="Champs obligatoires manquants.")

    phone = normalize_phone(data.phone)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO rsvps (full_name, phone, email, city, province) VALUES (?, ?, ?, ?, ?)",
                (data.full_name, phone, data.email, data.city, data.province)
            )
            row = conn.execute("SELECT last_insert_rowid() as id").fetchone()
            rid = row["id"]
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Ce numéro est déjà inscrit.")

    # Confirmation SMS (non-blocking mock if no Twilio creds)
    try:
        send_sms(
            phone,
            f"🇨🇦🇧🇯 Merci {data.full_name.split()[0]}! "
            f"Votre intention de vote pour les élections du Bénin (12 AVRIL) est enregistrée. "
            f"C'est ton moment — la diaspora canadienne fait entendre sa voix!"
        )
    except Exception as e:
        print(f"SMS confirmation error: {e}")

    return {"success": True, "id": rid, "message": "Inscription confirmée!"}


# GET /api/stats
@app.get("/api/stats")
async def stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as count FROM rsvps WHERE confirmed=1").fetchone()["count"]
        by_prov = conn.execute(
            "SELECT province, COUNT(*) as count FROM rsvps WHERE confirmed=1 GROUP BY province ORDER BY count DESC"
        ).fetchall()
    return {"total": total, "byProvince": [dict(r) for r in by_prov]}


# GET /api/admin/voters
@app.get("/api/admin/voters")
async def list_voters(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM rsvps ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


# POST /api/admin/blast
@app.post("/api/admin/blast")
async def sms_blast(data: BlastRequest, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    if not data.message:
        raise HTTPException(status_code=400, detail="Message requis.")

    # Build voter list based on targeting options
    if data.voter_ids:
        placeholders = ",".join("?" * len(data.voter_ids))
        query = f"SELECT id, phone, full_name FROM rsvps WHERE confirmed=1 AND id IN ({placeholders})"
        with get_db() as conn:
            voters = conn.execute(query, data.voter_ids).fetchall()
    else:
        query = "SELECT id, phone, full_name FROM rsvps WHERE confirmed=1"
        params = []
        if data.province:
            query += " AND province=?"
            params.append(data.province)
        query += " ORDER BY id ASC"
        if data.limit:
            query += f" LIMIT {int(data.limit)}"
        with get_db() as conn:
            voters = conn.execute(query, params).fetchall()

    sent = 0
    failed = 0
    errors = []

    for v in voters:
        msg = data.message.replace("{nom}", v["full_name"].split()[0])
        try:
            result = send_sms(v["phone"], msg)
            with get_db() as conn:
                conn.execute("UPDATE rsvps SET sms_sent=sms_sent+1 WHERE id=?", (v["id"],))
                conn.execute(
                    "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                    (v["phone"], msg, "sent", result["sid"])
                )
            sent += 1
        except Exception as e:
            failed += 1
            errors.append({"phone": v["phone"], "error": str(e)})
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO sms_log (phone, message, status) VALUES (?,?,?)",
                    (v["phone"], msg, "failed")
                )

    return {"success": True, "sent": sent, "failed": failed, "errors": errors}


# POST /api/admin/sms-single
@app.post("/api/admin/sms-single")
async def sms_single(data: SMSSingle, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    try:
        result = send_sms(data.phone, data.message)
        with get_db() as conn:
            conn.execute(
                "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                (data.phone, data.message, "sent", result["sid"])
            )
        return {"success": True, "sid": result["sid"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET /api/admin/sms-log
@app.get("/api/admin/sms-log")
async def sms_log(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sms_log ORDER BY sent_at DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]


# DELETE /api/admin/voter/{id}
@app.delete("/api/admin/voter/{voter_id}")
async def delete_voter(voter_id: int, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with get_db() as conn:
        conn.execute("DELETE FROM rsvps WHERE id=?", (voter_id,))
    return {"success": True}
