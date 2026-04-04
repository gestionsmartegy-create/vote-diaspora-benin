import csv
import io
import os
import secrets
import sqlite3
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Request, UploadFile, File, Cookie, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, RedirectResponse, HTMLResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioRestException

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")   # AC... (Account SID)
TWILIO_API_KEY     = os.getenv("TWILIO_API_KEY", "")        # SK... jamais dans le code
TWILIO_API_SECRET  = os.getenv("TWILIO_API_SECRET", "")     # Secret jamais dans le code
TWILIO_FROM        = os.getenv("TWILIO_PHONE_NUMBER", "")
ADMIN_PWD          = os.getenv("ADMIN_PASSWORD", "DORO2026")
SECRET_KEY         = os.getenv("SECRET_KEY", secrets.token_hex(32))
DB_PATH            = os.path.join(os.path.dirname(__file__), "votes.db")
SESSION_MAX_AGE    = 60 * 60 * 8  # 8 heures

# Auth: essaie API Key d'abord, fallback sur Auth Token
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")

def _make_twilio():
    if TWILIO_API_KEY and TWILIO_API_SECRET and TWILIO_ACCOUNT_SID:
        return TwilioClient(TWILIO_API_KEY, TWILIO_API_SECRET, TWILIO_ACCOUNT_SID)
    if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
        return TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    return None

twilio = _make_twilio()
signer   = URLSafeTimedSerializer(SECRET_KEY, salt="admin-session")

# Track failed login attempts per IP
_login_attempts: dict = {}  # ip -> [timestamp, ...]

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

def verify_session(session: Optional[str]) -> bool:
    """Vérifie le cookie de session signé."""
    if not session:
        return False
    try:
        signer.loads(session, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False

def require_admin(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    if not verify_session(session):
        raise HTTPException(status_code=401, detail="Session expirée ou invalide. Reconnectez-vous.")

def add_security_headers(response):
    """Ajoute les headers de sécurité HTTP à toutes les réponses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# Validation numéro E.164
_PHONE_RE = re.compile(r'^\+[1-9]\d{7,14}$')

# Anti-abus: compteur SMS par destinataire par jour
_sms_sent_today: dict = {}
MAX_SMS_PER_RECIPIENT_PER_DAY = 3
MAX_SMS_BODY_LENGTH = 320

def send_sms(to: str, body: str) -> dict:
    """Envoie SMS avec protections anti-abus. Clés 100% via env vars."""
    # 1. Validation format E.164
    if not _PHONE_RE.match(to):
        raise ValueError(f"Numéro invalide (format E.164 requis): {to}")
    # 2. Limite longueur
    if len(body) > MAX_SMS_BODY_LENGTH:
        raise ValueError(f"Message trop long ({len(body)} chars, max {MAX_SMS_BODY_LENGTH})")
    # 3. Anti-bombing: max 3 SMS/destinataire/jour
    today = datetime.utcnow().date().isoformat()
    key = f"{today}:{to}"
    count = _sms_sent_today.get(key, 0)
    if count >= MAX_SMS_PER_RECIPIENT_PER_DAY:
        raise ValueError(f"Limite journalière atteinte pour ce numéro")
    # 4. Mode mock si Twilio non configuré
    if not twilio or not TWILIO_FROM:
        print(f"[SMS MOCK] To={to} | {body[:80]}")
        _sms_sent_today[key] = count + 1
        return {"sid": f"MOCK_{secrets.token_hex(8)}"}
    # 5. Envoi réel via API Key (jamais hardcodée)
    msg = twilio.messages.create(body=body, from_=TWILIO_FROM, to=to)
    _sms_sent_today[key] = count + 1
    return {"sid": msg.sid}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    resp = FileResponse("public/index.html")
    return add_security_headers(resp)

@app.get("/admin.html")
async def admin_page(session: Optional[str] = Cookie(default=None, alias="admin_session")):
    """Protège admin.html côté serveur — redirige vers /login si pas de session valide."""
    if not verify_session(session):
        return RedirectResponse(url="/login", status_code=302)
    resp = FileResponse("public/admin.html")
    return add_security_headers(resp)

@app.get("/login")
async def login_page():
    """Page de login autonome — complètement séparée du panel admin."""
    html = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Accès Admin — Vote Diaspora</title>
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800&display=swap" rel="stylesheet"/>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Montserrat',sans-serif;background:#080e1c;color:#fff;min-height:100vh;
         display:flex;align-items:center;justify-content:center;padding:1rem;}
    .card{background:#0d1525;border:1px solid rgba(36,52,104,0.3);border-radius:14px;
          padding:2.5rem 2rem;width:100%;max-width:360px;text-align:center;}
    .card h1{font-size:1.4rem;margin-bottom:0.4rem;}
    .card p{font-size:0.82rem;color:rgba(255,255,255,0.4);margin-bottom:2rem;}
    .field{position:relative;margin-bottom:1rem;}
    input[type=password],input[type=text]{
      width:100%;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);
      border-radius:6px;color:#fff;font-size:1rem;padding:0.8rem 2.8rem 0.8rem 1rem;
      outline:none;font-family:inherit;transition:border-color 0.2s;}
    input:focus{border-color:#243468;}
    .eye{position:absolute;right:0.75rem;top:50%;transform:translateY(-50%);
         background:none;border:none;cursor:pointer;font-size:1rem;color:rgba(255,255,255,0.35);padding:0;}
    .btn{width:100%;background:#243468;color:#fff;border:none;border-radius:6px;
         font-size:1rem;font-weight:800;text-transform:uppercase;letter-spacing:2px;
         padding:0.9rem;cursor:pointer;transition:background 0.2s;margin-top:0.25rem;}
    .btn:hover{background:#1a2d6b;}
    .btn:disabled{opacity:0.5;cursor:not-allowed;}
    .err{color:#ff7070;font-size:0.78rem;margin-top:0.75rem;min-height:1.1rem;}
    .attempts{font-size:0.72rem;color:rgba(255,255,255,0.2);margin-top:1rem;}
  </style>
</head>
<body>
<div class="card">
  <h1>🔐 Accès Admin</h1>
  <p>Plateforme Vote Diaspora — Bénin 2026</p>
  <div class="field">
    <input type="password" id="pwd" placeholder="Mot de passe" autocomplete="current-password"/>
    <button class="eye" type="button" id="eye" onclick="toggleEye()">👁</button>
  </div>
  <button class="btn" id="btn" onclick="doLogin()">Accéder</button>
  <div class="err" id="err"></div>
  <div class="attempts" id="att"></div>
</div>
<script>
let tries = 0;
function toggleEye(){
  const i=document.getElementById('pwd');
  const e=document.getElementById('eye');
  i.type=i.type==='password'?'text':'password';
  e.textContent=i.type==='password'?'👁':'🙈';
}
document.getElementById('pwd').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
async function doLogin(){
  const pwd=document.getElementById('pwd').value.trim();
  const err=document.getElementById('err');
  const btn=document.getElementById('btn');
  err.textContent='';
  if(!pwd){err.textContent='⚠️ Entrez le mot de passe.';return;}
  btn.disabled=true;btn.textContent='⏳ Vérification…';
  try{
    const r=await fetch('/api/admin/login',{
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    if(r.ok){window.location.replace('/admin.html');return;}
    const d=await r.json();
    tries++;
    if(r.status===429){err.textContent='🚫 Trop de tentatives. Attendez quelques minutes.';}
    else if(r.status===401){err.textContent='❌ Mot de passe incorrect.'+( tries>=3?' Vérifiez la casse.':'');}
    else{err.textContent=`❌ Erreur ${r.status}. Réessayez.`;}
    if(tries>0)document.getElementById('att').textContent=`${tries} tentative(s) échouée(s)`;
    document.getElementById('pwd').focus();
    document.getElementById('pwd').select();
  }catch(e){err.textContent='❌ Impossible de joindre le serveur.';}
  btn.disabled=false;btn.textContent='Accéder';
}
</script>
</body>
</html>"""
    return HTMLResponse(content=html)

# POST /api/admin/login — crée une session HTTP-only
@app.post("/api/admin/login")
@limiter.limit("5/minute")  # max 5 tentatives / minute / IP
async def admin_login(request: Request, response: Response, body: dict):
    ip = get_remote_address(request)
    now = datetime.utcnow()

    # Nettoyage des tentatives anciennes (> 10 min)
    if ip in _login_attempts:
        _login_attempts[ip] = [t for t in _login_attempts[ip] if (now - t).seconds < 600]

    # Bloquer après 10 échecs en 10 min
    if len(_login_attempts.get(ip, [])) >= 10:
        raise HTTPException(status_code=429, detail="Trop de tentatives. Réessayez dans 10 minutes.")

    pwd = body.get("password", "")
    if pwd != ADMIN_PWD:
        _login_attempts.setdefault(ip, []).append(now)
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")

    # Réinitialiser compteur sur succès
    _login_attempts.pop(ip, None)

    # Créer token signé
    token = signer.dumps({"login": now.isoformat()})

    response.set_cookie(
        key="admin_session",
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,          # ← invisible au JS / DevTools Console
        secure=True,            # ← HTTPS uniquement en prod
        samesite="strict",      # ← protection CSRF
        path="/",
    )
    add_security_headers(response)
    return {"success": True}

# POST /api/admin/logout
@app.post("/api/admin/logout")
async def admin_logout(response: Response):
    response.delete_cookie(key="admin_session", path="/")
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
async def list_voters(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM rsvps ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


# ── External Contacts (CSV Import) ────────────────────────────────────────────

# POST /api/admin/import-csv
@app.post("/api/admin/import-csv")
async def import_csv(request: Request, file: UploadFile = File(...), session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)

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
async def list_external(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM external_contacts ORDER BY imported_at DESC").fetchall()
    return [dict(r) for r in rows]


# DELETE /api/admin/external-contacts  — clear all imported contacts
@app.delete("/api/admin/external-contacts")
async def clear_external(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        conn.execute("DELETE FROM external_contacts")
    return {"success": True}


# GET /api/admin/csv-template  — download blank template
@app.get("/api/admin/csv-template")
async def csv_template(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    sample = "nom,telephone,ville,province\nKouassi Adéchina,+15140000001,Montréal,Québec\nAmina Kone,+14160000002,Toronto,Ontario\n"
    return StreamingResponse(
        io.BytesIO(sample.encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=template-contacts-vote.csv"}
    )


# POST /api/admin/blast
@app.post("/api/admin/blast")
async def sms_blast(request: Request, data: BlastRequest, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
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
async def sms_single(request: Request, data: SMSSingle, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
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
async def sms_log(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sms_log ORDER BY sent_at DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]


# DELETE /api/admin/voter/{id}
@app.delete("/api/admin/voter/{voter_id}")
async def delete_voter(request: Request, voter_id: int, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        conn.execute("DELETE FROM rsvps WHERE id=?", (voter_id,))
    return {"success": True}
