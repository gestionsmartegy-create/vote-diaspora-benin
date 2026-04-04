import csv
import io
import os
import sqlite3
import re
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Request, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
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
ADMIN_PWD    = os.getenv("ADMIN_PASSWORD", "DORO2026")
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
            CREATE TABLE IF NOT EXISTS external_contacts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name   TEXT NOT NULL,
                phone       TEXT NOT NULL,
                city        TEXT DEFAULT '',
                province    TEXT DEFAULT '',
                sms_sent    INTEGER DEFAULT 0,
                imported_at TEXT DEFAULT (datetime('now'))
            );
        """)

# ── App Setup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print(f"\n🗳️  Serveur élections démarré")
    print(f"📊 Admin: /admin.html")
    print(f"🔑 Password admin: {ADMIN_PWD}\n")
    yield

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
    limit: Optional[int] = None
    voter_ids: Optional[list[int]] = None
    source: Optional[str] = "rsvp"        # "rsvp" | "external" | "both"
    external_ids: Optional[list[int]] = None

class SMSSingle(BaseModel):
    phone: str
    message: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def normalize_phone(phone: str) -> str:
    digits = re.sub(r"[\s\-().]", "", phone)
    # ensure +1 prefix for Canadian numbers
    if digits.startswith("1") and len(digits) == 11:
        digits = "+" + digits
    elif len(digits) == 10:
        digits = "+1" + digits
    return digits

def require_admin(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_PWD:
        raise HTTPException(status_code=401, detail="Non autorisé. Mot de passe incorrect.")

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

# POST /api/admin/login — validate password
@app.post("/api/admin/login")
async def admin_login(x_admin_token: str = Header(default="")):
    if x_admin_token != ADMIN_PWD:
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    return {"success": True}

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

    try:
        send_sms(
            phone,
            f"🇨🇦🇧🇯 Merci {data.full_name.split()[0]}! "
            f"Votre intention de vote pour les élections du Bénin (12 AVRIL) est enregistrée. "
            f"C'est ton moment — la diaspora fait entendre sa voix!"
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


# ── External Contacts (CSV Import) ────────────────────────────────────────────

# POST /api/admin/import-csv
@app.post("/api/admin/import-csv")
async def import_csv(file: UploadFile = File(...), x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)

    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Fichier CSV requis (.csv).")

    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # handle BOM
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))

    # normalize headers (lowercase, strip spaces)
    reader.fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]

    required = {"nom", "telephone"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise HTTPException(
            status_code=422,
            detail=f"Colonnes requises: nom, telephone. Trouvées: {reader.fieldnames}"
        )

    imported = 0
    skipped  = 0
    errors   = []

    with get_db() as conn:
        for i, row in enumerate(reader, start=2):
            nom   = str(row.get("nom", "") or "").strip()
            phone = normalize_phone(str(row.get("telephone", "") or "").strip())
            ville = str(row.get("ville", "") or "").strip()
            prov  = str(row.get("province", "") or "").strip()

            if not nom or not phone:
                skipped += 1
                continue

            try:
                conn.execute(
                    "INSERT INTO external_contacts (full_name, phone, city, province) VALUES (?,?,?,?)",
                    (nom, phone, ville, prov)
                )
                imported += 1
            except Exception as e:
                errors.append({"ligne": i, "erreur": str(e)})
                skipped += 1

    return {
        "success": True,
        "imported": imported,
        "skipped": skipped,
        "errors": errors[:10]  # cap error list
    }


# GET /api/admin/external-contacts
@app.get("/api/admin/external-contacts")
async def list_external(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM external_contacts ORDER BY imported_at DESC").fetchall()
    return [dict(r) for r in rows]


# DELETE /api/admin/external-contacts  — clear all imported contacts
@app.delete("/api/admin/external-contacts")
async def clear_external(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    with get_db() as conn:
        conn.execute("DELETE FROM external_contacts")
    return {"success": True}


# GET /api/admin/csv-template  — download blank template
@app.get("/api/admin/csv-template")
async def csv_template(x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    sample = "nom,telephone,ville,province\nKouassi Adéchina,+15140000001,Montréal,Québec\nAmina Kone,+14160000002,Toronto,Ontario\n"
    return StreamingResponse(
        io.BytesIO(sample.encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=template-contacts-vote.csv"}
    )


# POST /api/admin/blast
@app.post("/api/admin/blast")
async def sms_blast(data: BlastRequest, x_admin_token: str = Header(default="")):
    require_admin(x_admin_token)
    if not data.message:
        raise HTTPException(status_code=400, detail="Message requis.")

    contacts = []   # list of dicts with full_name, phone, id, source

    # ── Fetch RSVP contacts ───────────────────────────────────────────────────
    if data.source in ("rsvp", "both", None):
        if data.voter_ids:
            placeholders = ",".join("?" * len(data.voter_ids))
            query = f"SELECT id, phone, full_name FROM rsvps WHERE confirmed=1 AND id IN ({placeholders})"
            with get_db() as conn:
                rows = conn.execute(query, data.voter_ids).fetchall()
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
                rows = conn.execute(query, params).fetchall()
        contacts += [{"id": r["id"], "phone": r["phone"], "full_name": r["full_name"], "source": "rsvp"} for r in rows]

    # ── Fetch External contacts ───────────────────────────────────────────────
    if data.source in ("external", "both"):
        if data.external_ids:
            placeholders = ",".join("?" * len(data.external_ids))
            query = f"SELECT id, phone, full_name FROM external_contacts WHERE id IN ({placeholders})"
            with get_db() as conn:
                rows = conn.execute(query, data.external_ids).fetchall()
        else:
            query = "SELECT id, phone, full_name FROM external_contacts ORDER BY id ASC"
            if data.limit and data.source == "external":
                query += f" LIMIT {int(data.limit)}"
            with get_db() as conn:
                rows = conn.execute(query).fetchall()
        contacts += [{"id": r["id"], "phone": r["phone"], "full_name": r["full_name"], "source": "external"} for r in rows]

    sent = 0
    failed = 0
    errors = []

    for c in contacts:
        msg = data.message.replace("{nom}", c["full_name"].split()[0])
        try:
            result = send_sms(c["phone"], msg)
            table = "rsvps" if c["source"] == "rsvp" else "external_contacts"
            with get_db() as conn:
                conn.execute(f"UPDATE {table} SET sms_sent=sms_sent+1 WHERE id=?", (c["id"],))
                conn.execute(
                    "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                    (c["phone"], msg, "sent", result["sid"])
                )
            sent += 1
        except Exception as e:
            failed += 1
            errors.append({"phone": c["phone"], "error": str(e)})
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO sms_log (phone, message, status) VALUES (?,?,?)",
                    (c["phone"], msg, "failed")
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
