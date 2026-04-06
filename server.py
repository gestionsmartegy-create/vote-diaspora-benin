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
import africastalking

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")   # AC... (Account SID)
TWILIO_API_KEY     = os.getenv("TWILIO_API_KEY", "")        # SK... jamais dans le code
TWILIO_API_SECRET  = os.getenv("TWILIO_API_SECRET", "")     # Secret jamais dans le code
TWILIO_FROM        = os.getenv("TWILIO_PHONE_NUMBER", "")
ADMIN_PWD          = os.getenv("ADMIN_PASSWORD", "")  # must be set via env var
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

# ── Africa's Talking ──────────────────────────────────────────────────────────
AT_USERNAME = os.getenv("AT_USERNAME", "")
AT_API_KEY  = os.getenv("AT_API_KEY", "")

def _make_at_sms():
    if AT_USERNAME and AT_API_KEY:
        try:
            africastalking.initialize(AT_USERNAME, AT_API_KEY)
            return africastalking.SMS
        except Exception as e:
            print(f"[AT] Init error: {e}")
    return None

at_sms = _make_at_sms()

# Préfixes Canada/US → Twilio ; reste → Africa's Talking
CANADA_US_PREFIXES = ("+1",)

def route_provider(phone: str) -> str:
    for prefix in CANADA_US_PREFIXES:
        if phone.startswith(prefix):
            return "twilio"
    return "africastalking" if at_sms else "twilio"

# Track failed login attempts per IP
_login_attempts: dict = {}  # ip -> [timestamp, ...]

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "")  # Railway injecte automatiquement

USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    import psycopg2.errors

    class _PgConnWrapper:
        """Thin wrapper that makes psycopg2 connections work as context managers
        the same way SQLite connections do (auto-commit on __exit__)."""
        def __init__(self, conn):
            self._conn = conn

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            self._conn.close()
            return False

        # Delegate attribute access to the underlying connection so callers
        # that hold a reference to the wrapper can still call .commit() etc.
        def __getattr__(self, name):
            return getattr(self._conn, name)

    def get_db():
        conn = psycopg2.connect(DATABASE_URL)
        return _PgConnWrapper(conn)

else:
    class _SqliteConnWrapper:
        """Thin wrapper that preserves the existing SQLite context-manager
        behaviour while exposing the same interface as the Postgres wrapper."""
        def __init__(self, conn):
            self._conn = conn

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            self._conn.close()
            return False

        def __getattr__(self, name):
            return getattr(self._conn, name)

    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return _SqliteConnWrapper(conn)


# ── DB abstraction helpers ────────────────────────────────────────────────────
# These normalise the two main differences between SQLite and psycopg2:
#   1. Placeholder style: SQLite uses ?, psycopg2 uses %s
#   2. Cursor / row-dict access: SQLite returns Row objects via conn.execute();
#      psycopg2 needs an explicit cursor with RealDictCursor.

def _ph(sql: str) -> str:
    """Replace ? placeholders with %s for PostgreSQL."""
    return sql.replace("?", "%s") if USE_POSTGRES else sql


def db_execute(conn, sql: str, params=()):
    """Execute a write statement. Returns the cursor (for RETURNING etc.)."""
    sql = _ph(sql)
    if USE_POSTGRES:
        cur = conn._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return cur
    else:
        return conn._conn.execute(sql, params)


def db_fetchall(conn, sql: str, params=()):
    """Execute a SELECT and return all rows as a list of dicts."""
    sql = _ph(sql)
    if USE_POSTGRES:
        cur = conn._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    else:
        rows = conn._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def db_fetchone(conn, sql: str, params=()):
    """Execute a SELECT and return a single row as a dict, or None."""
    sql = _ph(sql)
    if USE_POSTGRES:
        cur = conn._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None
    else:
        row = conn._conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def _in_placeholders(n: int) -> str:
    """Return n comma-separated placeholders for an IN clause."""
    ph = "%s" if USE_POSTGRES else "?"
    return ",".join([ph] * n)


# ── UniqueViolation exception (DB-agnostic) ───────────────────────────────────
if USE_POSTGRES:
    _UniqueViolation = psycopg2.errors.UniqueViolation
else:
    _UniqueViolation = sqlite3.IntegrityError


def init_db():
    conn = get_db()
    if USE_POSTGRES:
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS rsvps (
                id          SERIAL PRIMARY KEY,
                full_name   TEXT NOT NULL,
                phone       TEXT NOT NULL UNIQUE,
                email       TEXT,
                city        TEXT NOT NULL,
                province    TEXT NOT NULL,
                confirmed   INTEGER DEFAULT 1,
                sms_sent    INTEGER DEFAULT 0,
                created_at  TIMESTAMP DEFAULT NOW()
            )""")
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS sms_log (
                id          SERIAL PRIMARY KEY,
                phone       TEXT NOT NULL,
                message     TEXT NOT NULL,
                status      TEXT,
                twilio_sid  TEXT,
                sent_at     TIMESTAMP DEFAULT NOW()
            )""")
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS external_contacts (
                id          SERIAL PRIMARY KEY,
                full_name   TEXT NOT NULL,
                phone       TEXT NOT NULL,
                city        TEXT DEFAULT '',
                province    TEXT DEFAULT '',
                sms_sent    INTEGER DEFAULT 0,
                imported_at TIMESTAMP DEFAULT NOW()
            )""")
    else:
        db_execute(conn, """
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
            )""")
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS sms_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                phone       TEXT NOT NULL,
                message     TEXT NOT NULL,
                status      TEXT,
                twilio_sid  TEXT,
                sent_at     TEXT DEFAULT (datetime('now'))
            )""")
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS external_contacts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name   TEXT NOT NULL,
                phone       TEXT NOT NULL,
                city        TEXT DEFAULT '',
                province    TEXT DEFAULT '',
                sms_sent    INTEGER DEFAULT 0,
                imported_at TEXT DEFAULT (datetime('now'))
            )""")
    conn._conn.commit()
    conn._conn.close()

# ── App Setup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print(f"\n🗳️  Serveur élections démarré — admin: /login\n")
    yield

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="public"), name="static")

# ── Schemas ───────────────────────────────────────────────────────────────────
RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_MIN_SCORE = 0.5  # score minimum (0.0 = bot, 1.0 = humain)

async def verify_recaptcha(token: str) -> bool:
    """Vérifie le token reCAPTCHA v3 côté serveur."""
    if not RECAPTCHA_SECRET or not token:
        return True  # bypass si pas configuré (dev mode)
    import urllib.request, urllib.parse, json as _json
    data = urllib.parse.urlencode({
        "secret": RECAPTCHA_SECRET,
        "response": token
    }).encode()
    try:
        req = urllib.request.Request("https://www.google.com/recaptcha/api/siteverify", data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = _json.loads(resp.read())
            return result.get("success") and result.get("score", 0) >= RECAPTCHA_MIN_SCORE
    except Exception:
        return True  # fail open pour ne pas bloquer si Google down

class RSVPCreate(BaseModel):
    full_name: str
    phone: str
    email: Optional[str] = None
    city: str
    province: str
    recaptcha_token: Optional[str] = None

class BlastRequest(BaseModel):
    message: str
    province: Optional[str] = None
    limit: Optional[int] = None
    voter_ids: Optional[list[int]] = None
    source: Optional[str] = "rsvp"        # "rsvp" | "external" | "both"
    external_ids: Optional[list[int]] = None
    channel: Optional[str] = "sms"        # "sms" | "whatsapp"

class SMSSingle(BaseModel):
    phone: str
    message: str
    channel: Optional[str] = "sms"        # "sms" | "whatsapp"

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

def send_message(to: str, body: str, channel: str = "sms") -> dict:
    """Envoie SMS ou WhatsApp avec protections anti-abus."""
    # 1. Validation format E.164
    if not _PHONE_RE.match(to):
        raise ValueError(f"Numéro invalide (format E.164 requis): {to}")
    # 2. Limite longueur
    if len(body) > MAX_SMS_BODY_LENGTH:
        raise ValueError(f"Message trop long ({len(body)} chars, max {MAX_SMS_BODY_LENGTH})")
    # 3. Anti-bombing: max 3 messages/destinataire/jour
    today = datetime.utcnow().date().isoformat()
    key = f"{today}:{channel}:{to}"
    count = _sms_sent_today.get(key, 0)
    if count >= MAX_SMS_PER_RECIPIENT_PER_DAY:
        raise ValueError(f"Limite journalière atteinte pour ce numéro")
    # 4. Mode mock si Twilio non configuré
    if not twilio or not TWILIO_FROM:
        print(f"[{channel.upper()} MOCK] To={to} | {body[:80]}")
        _sms_sent_today[key] = count + 1
        return {"sid": f"MOCK_{secrets.token_hex(8)}"}
    # 5. Envoi réel — routage hybride Twilio / Africa's Talking
    provider = route_provider(to)
    if channel == "whatsapp":
        # WhatsApp toujours via Twilio
        if not twilio or not TWILIO_FROM:
            raise ValueError("Twilio non configuré pour WhatsApp")
        msg = twilio.messages.create(
            body=body,
            from_=f"whatsapp:{TWILIO_FROM}",
            to=f"whatsapp:{to}"
        )
        _sms_sent_today[key] = count + 1
        return {"sid": msg.sid, "channel": "whatsapp", "provider": "twilio"}
    elif provider == 'africastalking' and at_sms:
        # SMS international → Africa's Talking
        response = at_sms.send(body, [to])
        results  = response.get('SMSMessageData', {}).get('Recipients', [])
        sid = results[0].get('messageId', 'AT_UNKNOWN') if results else 'AT_UNKNOWN'
        status = results[0].get('status', 'unknown') if results else 'unknown'
        if status not in ('Success', 'success'):
            raise ValueError(f"AT error: {status}")
        _sms_sent_today[key] = count + 1
        return {"sid": sid, "channel": "sms", "provider": "africastalking"}
    else:
        # SMS Canada/US → Twilio
        if not twilio or not TWILIO_FROM:
            raise ValueError("Twilio non configuré")
        msg = twilio.messages.create(body=body, from_=TWILIO_FROM, to=to)
        _sms_sent_today[key] = count + 1
        return {"sid": msg.sid, "channel": "sms", "provider": "twilio"}

# Alias rétrocompatible
def send_sms(to: str, body: str) -> dict:
    return send_message(to, body, "sms")

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
    # Vérification reCAPTCHA v3
    if RECAPTCHA_SECRET:
        is_human = await verify_recaptcha(data.recaptcha_token or "")
        if not is_human:
            raise HTTPException(status_code=403, detail="Vérification anti-bot échouée. Rafraîchissez la page.")

    if not data.full_name or not data.phone or not data.city or not data.province:
        raise HTTPException(status_code=400, detail="Champs obligatoires manquants.")

    phone = normalize_phone(data.phone)

    try:
        with get_db() as conn:
            if USE_POSTGRES:
                cur = db_execute(
                    conn,
                    "INSERT INTO rsvps (full_name, phone, email, city, province) VALUES (?, ?, ?, ?, ?) RETURNING id",
                    (data.full_name, phone, data.email, data.city, data.province)
                )
                rid = cur.fetchone()["id"]
            else:
                db_execute(
                    conn,
                    "INSERT INTO rsvps (full_name, phone, email, city, province) VALUES (?, ?, ?, ?, ?)",
                    (data.full_name, phone, data.email, data.city, data.province)
                )
                rid = db_fetchone(conn, "SELECT last_insert_rowid() as id")["id"]
    except _UniqueViolation:
        raise HTTPException(status_code=409, detail="Ce numéro est déjà inscrit.")

    # ── SMS de confirmation avec mention légale de désinscription ─────────────
    nom_court = data.full_name.split()[0]
    sms_confirmation = (
        f"🗳️ Merci {nom_court}! Votre engagement pour les élections du Bénin "
        f"(12 AVRIL) est confirmé. La diaspora béninoise fait entendre sa voix!\n"
        f"Plus loin ensemble 🇧🇯\n"
        f"Répondez STOP pour vous désabonner."
    )
    try:
        result = send_sms(phone, sms_confirmation)
        with get_db() as conn:
            db_execute(
                conn,
                "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                (phone, sms_confirmation, "sent", result["sid"])
            )
            db_execute(conn, "UPDATE rsvps SET sms_sent=1 WHERE id=?", (rid,))
    except Exception as e:
        print(f"[SMS confirmation] {e}")

    return {"success": True, "id": rid, "message": "Inscription confirmée!"}


# GET /api/stats
@app.get("/api/stats")
async def stats():
    with get_db() as conn:
        total_row = db_fetchone(conn, "SELECT COUNT(*) as count FROM rsvps WHERE confirmed=1")
        total = total_row["count"]
        by_prov = db_fetchall(
            conn,
            "SELECT province, COUNT(*) as count FROM rsvps WHERE confirmed=1 GROUP BY province ORDER BY count DESC"
        )
    return {"total": total, "byProvince": by_prov}


# GET /api/admin/voters
@app.get("/api/admin/voters")
async def list_voters(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        rows = db_fetchall(conn, "SELECT * FROM rsvps ORDER BY created_at DESC")
    return rows


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
                db_execute(
                    conn,
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
        rows = db_fetchall(conn, "SELECT * FROM external_contacts ORDER BY imported_at DESC")
    return rows


# DELETE /api/admin/external-contacts  — clear all imported contacts
@app.delete("/api/admin/external-contacts")
async def clear_external(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        db_execute(conn, "DELETE FROM external_contacts")
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
            placeholders = _in_placeholders(len(data.voter_ids))
            query = f"SELECT id, phone, full_name FROM rsvps WHERE confirmed=1 AND id IN ({placeholders})"
            with get_db() as conn:
                rows = db_fetchall(conn, query, data.voter_ids)
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
                rows = db_fetchall(conn, query, params)
        contacts += [{"id": r["id"], "phone": r["phone"], "full_name": r["full_name"], "source": "rsvp"} for r in rows]

    # ── Fetch External contacts ───────────────────────────────────────────────
    if data.source in ("external", "both"):
        if data.external_ids:
            placeholders = _in_placeholders(len(data.external_ids))
            query = f"SELECT id, phone, full_name FROM external_contacts WHERE id IN ({placeholders})"
            with get_db() as conn:
                rows = db_fetchall(conn, query, data.external_ids)
        else:
            query = "SELECT id, phone, full_name FROM external_contacts ORDER BY id ASC"
            if data.limit and data.source == "external":
                query += f" LIMIT {int(data.limit)}"
            with get_db() as conn:
                rows = db_fetchall(conn, query)
        contacts += [{"id": r["id"], "phone": r["phone"], "full_name": r["full_name"], "source": "external"} for r in rows]

    sent = 0
    failed = 0
    errors = []

    # Ajouter mention STOP légale si absente du message
    base_message = data.message
    if "STOP" not in base_message.upper():
        base_message = base_message.rstrip() + "\nRépondez STOP pour vous désabonner."

    for c in contacts:
        msg = base_message.replace("{nom}", c["full_name"].split()[0])
        try:
            result = send_message(c["phone"], msg, data.channel or "sms")
            table = "rsvps" if c["source"] == "rsvp" else "external_contacts"
            with get_db() as conn:
                db_execute(conn, f"UPDATE {table} SET sms_sent=sms_sent+1 WHERE id=?", (c["id"],))
                db_execute(
                    conn,
                    "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                    (c["phone"], msg, f'sent_{data.channel or "sms"}', result["sid"])
                )
            sent += 1
        except Exception as e:
            failed += 1
            errors.append({"phone": c["phone"], "error": str(e)})
            with get_db() as conn:
                db_execute(
                    conn,
                    "INSERT INTO sms_log (phone, message, status) VALUES (?,?,?)",
                    (c["phone"], msg, "failed")
                )

    return {"success": True, "sent": sent, "failed": failed, "errors": errors}


# POST /api/admin/sms-single
@app.post("/api/admin/sms-single")
async def sms_single(request: Request, data: SMSSingle, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    try:
        msg = data.message
        if "STOP" not in msg.upper():
            msg = msg.rstrip() + "\nRépondez STOP pour vous désabonner."
        result = send_message(data.phone, msg, data.channel or "sms")
        with get_db() as conn:
            db_execute(
                conn,
                "INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?,?,?,?)",
                (data.phone, msg, "sent", result["sid"])
            )
        return {"success": True, "sid": result["sid"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET /api/admin/sms-log
@app.get("/api/admin/sms-log")
async def sms_log(request: Request, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        rows = db_fetchall(conn, "SELECT * FROM sms_log ORDER BY sent_at DESC LIMIT 200")
    return rows


# DELETE /api/admin/voter/{id}
@app.delete("/api/admin/voter/{voter_id}")
async def delete_voter(request: Request, voter_id: int, session: Optional[str] = Cookie(default=None, alias="admin_session")):
    require_admin(request, session)
    with get_db() as conn:
        db_execute(conn, "DELETE FROM rsvps WHERE id=?", (voter_id,))
    return {"success": True}
