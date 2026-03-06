const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const { Resend } = require('resend');
const DEFAULT_CARDS = require('./seeds');

const JWT_SECRET = process.env.JWT_SECRET || 'quizzery-jwt-secret-change-in-production';
const PORT = process.env.PORT || 3000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ── Database setup ─────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'quizzery.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    front TEXT NOT NULL,
    back TEXT NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0,
    memorized INTEGER NOT NULL DEFAULT 0,
    seen_at TEXT,
    memorized_at TEXT,
    nailed INTEGER NOT NULL DEFAULT 0,
    nailed_at TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    passage TEXT NOT NULL,
    notes TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── Migrate existing databases ─────────────────────────────────
try { db.exec('ALTER TABLE cards ADD COLUMN seen INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE cards ADD COLUMN memorized INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch {}
try { db.exec('ALTER TABLE cards ADD COLUMN seen_at TEXT'); } catch {}
try { db.exec('ALTER TABLE cards ADD COLUMN memorized_at TEXT'); } catch {}
try { db.exec('ALTER TABLE cards ADD COLUMN nailed INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE cards ADD COLUMN nailed_at TEXT'); } catch {}

// ── App setup ──────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..'))); // serve static files from project root

// ── Page routes ────────────────────────────────────────────────
app.get('/memorize', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'memorize.html'));
});

app.get('/read', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'read.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'reset-password.html'));
});

app.get('/profile', (_, res) => {
  res.sendFile(path.join(__dirname, '..', 'profile.html'));
});

// ── Auth middleware ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Auth routes ────────────────────────────────────────────────
app.post('/auth/signup', async (req, res) => {
  const { username, password, email } = req.body ?? {};
  if (!email?.trim() || !username?.trim() || !password) {
    return res.status(400).json({ error: 'Email, username, and password are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (username.trim().length < 2) {
    return res.status(400).json({ error: 'Username must be at least 2 characters.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  const existingUsername = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (existingUsername) {
    return res.status(409).json({ error: 'Username already exists.' });
  }

  const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(email.trim());
  if (existingEmail) {
    return res.status(409).json({ error: 'Email already exists.' });
  }

  const hash = await bcrypt.hash(password, 10);
  const { lastInsertRowid: userId } = db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  ).run(username.trim(), email.trim(), hash);

  // Seed default cards in a transaction
  const insertCard = db.prepare(
    'INSERT INTO cards (user_id, front, back) VALUES (?, ?, ?)'
  );
  db.transaction(() => {
    for (const card of DEFAULT_CARDS) {
      insertCard.run(userId, card.front, card.back);
    }
  })();

  const token = jwt.sign({ id: userId, username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: username.trim() });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim());
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body ?? {};
  res.json({ ok: true }); // always 200 to prevent email enumeration
  if (!email) return;
  const user = db.prepare('SELECT id, username FROM users WHERE email = ?').get(email.trim());
  if (!user) return;

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour
  db.prepare('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)')
    .run(user.id, token, expiresAt);

  const resetUrl = `https://dontforgetbible.com/reset-password?token=${token}`;
  await resend.emails.send({
    from: "Don't Forget! Bible <noreply@dontforgetbible.com>",
    to: email.trim(),
    subject: "Reset your Don't Forget! Bible password",
    html: `<p>Hi ${user.username},</p>
           <p>Click the link below to reset your password. This link expires in 1 hour.</p>
           <p><a href="${resetUrl}">${resetUrl}</a></p>
           <p>If you didn't request this, you can ignore this email.</p>`,
  });
});

app.post('/auth/reset-password', async (req, res) => {
  const { token, password } = req.body ?? {};
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const row = db.prepare('SELECT * FROM password_reset_tokens WHERE token = ?').get(token);
  if (!row) return res.status(400).json({ error: 'Invalid or expired reset link.' });
  if (row.used) return res.status(400).json({ error: 'This reset link has already been used.' });
  if (Date.now() > row.expires_at) return res.status(400).json({ error: 'This reset link has expired.' });

  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, row.user_id);
  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').run(row.id);

  res.json({ ok: true });
});

// ── Profile routes ─────────────────────────────────────────────
app.get('/profile/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT username, email FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
});

app.put('/profile/username', requireAuth, async (req, res) => {
  const { username } = req.body ?? {};
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.trim().length < 2) return res.status(400).json({ error: 'Username must be at least 2 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').get(username.trim(), req.user.id);
  if (existing) return res.status(409).json({ error: 'Username already exists.' });

  db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username.trim(), req.user.id);
  const newToken = jwt.sign({ id: req.user.id, username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token: newToken, username: username.trim() });
});

// ── Card routes ────────────────────────────────────────────────
app.get('/cards', requireAuth, (req, res) => {
  const cards = db.prepare(
    'SELECT id, front, back, seen, memorized, seen_at, memorized_at, nailed, nailed_at FROM cards WHERE user_id = ? ORDER BY id'
  ).all(req.user.id);
  res.json(cards);
});

app.post('/cards', requireAuth, (req, res) => {
  const { front, back } = req.body ?? {};
  if (!front || !back) {
    return res.status(400).json({ error: 'Front and back are required.' });
  }
  const { lastInsertRowid: id } = db.prepare(
    'INSERT INTO cards (user_id, front, back) VALUES (?, ?, ?)'
  ).run(req.user.id, front, back);
  res.json({ id, front, back, seen: 0, memorized: 0 });
});

app.put('/cards/:id', requireAuth, (req, res) => {
  const card = db.prepare(
    'SELECT * FROM cards WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.id);
  if (!card) return res.status(404).json({ error: 'Card not found.' });

  const front = req.body.front ?? card.front;
  const back = req.body.back ?? card.back;
  const seen = req.body.seen !== undefined ? req.body.seen : card.seen;
  const memorized = req.body.memorized !== undefined ? req.body.memorized : card.memorized;

  let seenAt = card.seen_at ?? null;
  if (req.body.seen !== undefined) {
    if (req.body.seen && !card.seen) seenAt = new Date().toISOString();
    else if (!req.body.seen) seenAt = null;
  }

  let memorizedAt = card.memorized_at ?? null;
  if (req.body.memorized !== undefined) {
    if (req.body.memorized && !card.memorized) memorizedAt = new Date().toISOString();
    else if (!req.body.memorized) memorizedAt = null;
  }

  const nailed = req.body.nailed !== undefined ? req.body.nailed : card.nailed;
  let nailedAt = card.nailed_at ?? null;
  if (req.body.nailed !== undefined) {
    if (req.body.nailed && !card.nailed) nailedAt = new Date().toISOString();
    else if (!req.body.nailed) nailedAt = null;
  }

  db.prepare(
    'UPDATE cards SET front = ?, back = ?, seen = ?, memorized = ?, seen_at = ?, memorized_at = ?, nailed = ?, nailed_at = ? WHERE id = ?'
  ).run(front, back, seen, memorized, seenAt, memorizedAt, nailed, nailedAt, card.id);

  res.json({ id: card.id, front, back, seen, memorized, seen_at: seenAt, memorized_at: memorizedAt, nailed, nailed_at: nailedAt });
});

app.delete('/cards/:id', requireAuth, (req, res) => {
  const result = db.prepare(
    'DELETE FROM cards WHERE id = ? AND user_id = ?'
  ).run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Card not found.' });
  res.json({ success: true });
});

// ── Readings routes ────────────────────────────────────────────
app.get('/readings', requireAuth, (req, res) => {
  const readings = db.prepare(
    'SELECT id, date, passage, notes FROM readings WHERE user_id = ? ORDER BY date DESC, id DESC'
  ).all(req.user.id);
  res.json(readings);
});

app.post('/readings', requireAuth, (req, res) => {
  const { date, passage, notes } = req.body ?? {};
  if (!date || !passage?.trim()) {
    return res.status(400).json({ error: 'Date and passage are required.' });
  }
  const { lastInsertRowid: id } = db.prepare(
    'INSERT INTO readings (user_id, date, passage, notes) VALUES (?, ?, ?, ?)'
  ).run(req.user.id, date, passage.trim(), notes?.trim() || '');
  res.json({ id, date, passage: passage.trim(), notes: notes?.trim() || '' });
});

app.put('/readings/:id', requireAuth, (req, res) => {
  const reading = db.prepare(
    'SELECT * FROM readings WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.id);
  if (!reading) return res.status(404).json({ error: 'Reading not found.' });

  const date = req.body.date ?? reading.date;
  const passage = req.body.passage?.trim() ?? reading.passage;
  const notes = req.body.notes?.trim() ?? reading.notes;

  if (!passage) return res.status(400).json({ error: 'Passage is required.' });

  db.prepare(
    'UPDATE readings SET date = ?, passage = ?, notes = ? WHERE id = ?'
  ).run(date, passage, notes, reading.id);

  res.json({ id: reading.id, date, passage, notes });
});

app.delete('/readings/:id', requireAuth, (req, res) => {
  const result = db.prepare(
    'DELETE FROM readings WHERE id = ? AND user_id = ?'
  ).run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Reading not found.' });
  res.json({ success: true });
});

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Don't Forget! Bible running at http://localhost:${PORT}`);
});
