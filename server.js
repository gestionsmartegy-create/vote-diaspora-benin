require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const twilio = require('twilio');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database Setup ────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'votes.db'));

db.exec(`
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
`);

// ── Twilio Client ─────────────────────────────────────────────────────────────
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,
  message: { error: 'Trop de requêtes, réessayez dans 15 minutes.' }
});
app.use('/api/', limiter);

// ── Admin Auth Middleware ──────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Non autorisé.' });
  }
  next();
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// POST /api/rsvp — Register a voter intention
app.post('/api/rsvp', (req, res) => {
  const { full_name, phone, email, city, province } = req.body;

  if (!full_name || !phone || !city || !province) {
    return res.status(400).json({ error: 'Champs obligatoires manquants.' });
  }

  // Normalize phone: keep digits + leading +
  const normalizedPhone = phone.replace(/[\s\-().]/g, '');

  try {
    const stmt = db.prepare(`
      INSERT INTO rsvps (full_name, phone, email, city, province)
      VALUES (?, ?, ?, ?, ?)
    `);
    const result = stmt.run(full_name, normalizedPhone, email || null, city, province);

    // Send confirmation SMS
    sendSMS(
      normalizedPhone,
      `🇨🇦🇧🇯 Merci ${full_name}! Votre intention de vote pour les élections du Bénin (12 AVRIL) est enregistrée. C'est ton moment — faites entendre la voix de la diaspora canadienne!`
    ).catch(err => console.error('SMS confirmation error:', err));

    res.json({ success: true, id: result.lastInsertRowid, message: 'Inscription confirmée! Un SMS de confirmation vous sera envoyé.' });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'Ce numéro est déjà inscrit.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// GET /api/stats — Public stats
app.get('/api/stats', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count FROM rsvps WHERE confirmed = 1').get();
  const byProvince = db.prepare(`
    SELECT province, COUNT(*) as count FROM rsvps WHERE confirmed = 1
    GROUP BY province ORDER BY count DESC
  `).all();
  res.json({ total: total.count, byProvince });
});

// ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

// GET /api/admin/voters — List all voters
app.get('/api/admin/voters', requireAdmin, (req, res) => {
  const voters = db.prepare('SELECT * FROM rsvps ORDER BY created_at DESC').all();
  res.json(voters);
});

// POST /api/admin/blast — Send SMS to all or filtered voters
app.post('/api/admin/blast', requireAdmin, async (req, res) => {
  const { message, province } = req.body;

  if (!message) return res.status(400).json({ error: 'Message requis.' });

  let query = 'SELECT id, phone, full_name FROM rsvps WHERE confirmed = 1';
  const params = [];
  if (province) {
    query += ' AND province = ?';
    params.push(province);
  }

  const voters = db.prepare(query).all(...params);
  if (voters.length === 0) {
    return res.json({ success: true, sent: 0, message: 'Aucun destinataire trouvé.' });
  }

  let sent = 0;
  let failed = 0;
  const errors = [];

  for (const voter of voters) {
    const personalizedMsg = message.replace('{nom}', voter.full_name.split(' ')[0]);
    try {
      const result = await sendSMS(voter.phone, personalizedMsg);
      db.prepare('UPDATE rsvps SET sms_sent = sms_sent + 1 WHERE id = ?').run(voter.id);
      db.prepare('INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?, ?, ?, ?)')
        .run(voter.phone, personalizedMsg, 'sent', result.sid);
      sent++;
    } catch (err) {
      failed++;
      errors.push({ phone: voter.phone, error: err.message });
      db.prepare('INSERT INTO sms_log (phone, message, status) VALUES (?, ?, ?)')
        .run(voter.phone, personalizedMsg, 'failed');
    }
  }

  res.json({ success: true, sent, failed, errors });
});

// POST /api/admin/sms-single — Send SMS to one voter
app.post('/api/admin/sms-single', requireAdmin, async (req, res) => {
  const { phone, message } = req.body;
  if (!phone || !message) return res.status(400).json({ error: 'Champs requis.' });

  try {
    const result = await sendSMS(phone, message);
    db.prepare('INSERT INTO sms_log (phone, message, status, twilio_sid) VALUES (?, ?, ?, ?)')
      .run(phone, message, 'sent', result.sid);
    res.json({ success: true, sid: result.sid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/sms-log — View SMS history
app.get('/api/admin/sms-log', requireAdmin, (req, res) => {
  const logs = db.prepare('SELECT * FROM sms_log ORDER BY sent_at DESC LIMIT 200').all();
  res.json(logs);
});

// DELETE /api/admin/voter/:id — Remove a voter
app.delete('/api/admin/voter/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM rsvps WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ── SMS Helper ────────────────────────────────────────────────────────────────
async function sendSMS(to, body) {
  return twilioClient.messages.create({
    body,
    from: process.env.TWILIO_PHONE_NUMBER,
    to
  });
}

// ── Start Server ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🗳️  Serveur élections démarré sur http://localhost:${PORT}`);
  console.log(`📊 Admin panel: http://localhost:${PORT}/admin.html`);
  console.log(`🔑 Mot de passe admin: ${process.env.ADMIN_PASSWORD || '(non défini)'}\n`);
});
