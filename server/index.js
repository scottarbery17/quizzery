const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const path = require('path');
const { Resend } = require('resend');
const DEFAULT_CARDS = require('./seeds');

const JWT_SECRET = process.env.JWT_SECRET || 'quizzery-jwt-secret-change-in-production';
const PORT = process.env.PORT || 8080;
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

  CREATE TABLE IF NOT EXISTS tribes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    leader_user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (leader_user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS tribe_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tribe_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tribe_id) REFERENCES tribes(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id)
  );

  CREATE TABLE IF NOT EXISTS tribe_invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tribe_id INTEGER NOT NULL,
    inviter_user_id INTEGER NOT NULL,
    invitee_user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tribe_id) REFERENCES tribes(id) ON DELETE CASCADE,
    FOREIGN KEY (inviter_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invitee_user_id) REFERENCES users(id) ON DELETE CASCADE
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

app.get('/tribe', (_, res) => {
  res.sendFile(path.join(__dirname, '..', 'tribe.html'));
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
    'SELECT id, front, back, seen, memorized, seen_at, memorized_at, nailed, nailed_at FROM cards WHERE user_id = ? ORDER BY id DESC'
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

app.post('/cards/reset', requireAuth, (req, res) => {
  db.prepare(
    'UPDATE cards SET seen = 0, memorized = 0, seen_at = NULL, memorized_at = NULL, nailed = 0, nailed_at = NULL WHERE user_id = ?'
  ).run(req.user.id);
  res.json({ ok: true });
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

// ── Tribe routes ───────────────────────────────────────────────

app.post('/tribes', requireAuth, (req, res) => {
  const { name } = req.body ?? {};
  if (!name?.trim()) {
    return res.status(400).json({ error: 'Tribe name is required.' });
  }

  const existing = db.prepare('SELECT id FROM tribe_members WHERE user_id = ?').get(req.user.id);
  if (existing) {
    return res.status(409).json({ error: 'You are already in a tribe.' });
  }

  const createTribe = db.transaction(() => {
    const { lastInsertRowid: tribeId } = db.prepare(
      'INSERT INTO tribes (name, leader_user_id) VALUES (?, ?)'
    ).run(name.trim(), req.user.id);
    db.prepare('INSERT INTO tribe_members (tribe_id, user_id) VALUES (?, ?)').run(tribeId, req.user.id);
    return tribeId;
  });

  const tribeId = createTribe();
  res.json({ id: tribeId, name: name.trim(), leader_user_id: req.user.id });
});

app.get('/tribes/my', requireAuth, (req, res) => {
  const membership = db.prepare('SELECT tribe_id FROM tribe_members WHERE user_id = ?').get(req.user.id);

  if (!membership) {
    const invitesReceived = db.prepare(`
      SELECT ti.id, ti.tribe_id, t.name AS tribe_name, u.username AS inviter_username, ti.created_at
      FROM tribe_invitations ti
      JOIN tribes t ON t.id = ti.tribe_id
      JOIN users u ON u.id = ti.inviter_user_id
      WHERE ti.invitee_user_id = ? AND ti.status = 'pending'
      ORDER BY ti.created_at DESC
    `).all(req.user.id);
    return res.json({ tribe: null, invitesReceived });
  }

  const tribe = db.prepare('SELECT id, name, leader_user_id FROM tribes WHERE id = ?').get(membership.tribe_id);
  if (!tribe) return res.status(404).json({ error: 'Tribe not found.' });

  const members = db.prepare(`
    SELECT u.id, u.username, tm.joined_at
    FROM tribe_members tm
    JOIN users u ON u.id = tm.user_id
    WHERE tm.tribe_id = ?
    ORDER BY tm.joined_at ASC
  `).all(tribe.id);

  const invitesSent = db.prepare(`
    SELECT ti.id, ti.invitee_user_id, u.username AS invitee_username, ti.status, ti.created_at
    FROM tribe_invitations ti
    JOIN users u ON u.id = ti.invitee_user_id
    WHERE ti.tribe_id = ? AND ti.status = 'pending'
    ORDER BY ti.created_at DESC
  `).all(tribe.id);

  const invitesReceived = db.prepare(`
    SELECT ti.id, ti.tribe_id, t.name AS tribe_name, u.username AS inviter_username, ti.created_at
    FROM tribe_invitations ti
    JOIN tribes t ON t.id = ti.tribe_id
    JOIN users u ON u.id = ti.inviter_user_id
    WHERE ti.invitee_user_id = ? AND ti.status = 'pending'
    ORDER BY ti.created_at DESC
  `).all(req.user.id);

  res.json({ tribe, members, invitesSent, invitesReceived });
});

app.post('/tribes/invite', requireAuth, (req, res) => {
  const { username } = req.body ?? {};
  if (!username?.trim()) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  const membership = db.prepare('SELECT tribe_id FROM tribe_members WHERE user_id = ?').get(req.user.id);
  if (!membership) {
    return res.status(403).json({ error: 'You must be in a tribe to invite members.' });
  }

  const tribe = db.prepare('SELECT id, name, leader_user_id FROM tribes WHERE id = ?').get(membership.tribe_id);
  if (!tribe) return res.status(404).json({ error: 'Tribe not found.' });

  const memberCount = db.prepare('SELECT COUNT(*) AS cnt FROM tribe_members WHERE tribe_id = ?').get(tribe.id);
  if (memberCount.cnt >= 12) {
    return res.status(400).json({ error: 'Tribe is full (max 12 members).' });
  }

  const invitee = db.prepare('SELECT id, username FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!invitee) {
    return res.status(404).json({ error: 'User not found.' });
  }

  if (invitee.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot invite yourself.' });
  }

  const inviteeMembership = db.prepare('SELECT id FROM tribe_members WHERE user_id = ?').get(invitee.id);
  if (inviteeMembership) {
    return res.status(409).json({ error: 'That user is already in a tribe.' });
  }

  const existingInvite = db.prepare(`
    SELECT id FROM tribe_invitations
    WHERE tribe_id = ? AND invitee_user_id = ? AND status = 'pending'
  `).get(tribe.id, invitee.id);
  if (existingInvite) {
    return res.status(409).json({ error: 'An invite to this user is already pending.' });
  }

  const { lastInsertRowid: inviteId } = db.prepare(
    'INSERT INTO tribe_invitations (tribe_id, inviter_user_id, invitee_user_id) VALUES (?, ?, ?)'
  ).run(tribe.id, req.user.id, invitee.id);

  res.json({ id: inviteId, tribe_id: tribe.id, invitee_username: invitee.username, status: 'pending' });
});

app.post('/tribes/invite/:id/respond', requireAuth, (req, res) => {
  const { action } = req.body ?? {};
  if (action !== 'accept' && action !== 'decline') {
    return res.status(400).json({ error: 'Action must be "accept" or "decline".' });
  }

  const invite = db.prepare(`
    SELECT * FROM tribe_invitations WHERE id = ? AND invitee_user_id = ? AND status = 'pending'
  `).get(req.params.id, req.user.id);

  if (!invite) {
    return res.status(404).json({ error: 'Invite not found or already responded.' });
  }

  if (action === 'decline') {
    db.prepare("UPDATE tribe_invitations SET status = 'declined' WHERE id = ?").run(invite.id);
    return res.json({ ok: true, action: 'declined' });
  }

  const tribe = db.prepare('SELECT id FROM tribes WHERE id = ?').get(invite.tribe_id);
  if (!tribe) {
    db.prepare("UPDATE tribe_invitations SET status = 'declined' WHERE id = ?").run(invite.id);
    return res.status(404).json({ error: 'Tribe no longer exists.' });
  }

  const existingMembership = db.prepare('SELECT id FROM tribe_members WHERE user_id = ?').get(req.user.id);
  if (existingMembership) {
    return res.status(409).json({ error: 'You are already in a tribe.' });
  }

  const memberCount = db.prepare('SELECT COUNT(*) AS cnt FROM tribe_members WHERE tribe_id = ?').get(tribe.id);
  if (memberCount.cnt >= 12) {
    return res.status(400).json({ error: 'Tribe is full (max 12 members).' });
  }

  const acceptAndJoin = db.transaction(() => {
    db.prepare("UPDATE tribe_invitations SET status = 'accepted' WHERE id = ?").run(invite.id);
    db.prepare('INSERT INTO tribe_members (tribe_id, user_id) VALUES (?, ?)').run(tribe.id, req.user.id);
    db.prepare(`
      UPDATE tribe_invitations SET status = 'declined'
      WHERE invitee_user_id = ? AND id != ? AND status = 'pending'
    `).run(req.user.id, invite.id);
  });

  acceptAndJoin();
  res.json({ ok: true, action: 'accepted', tribe_id: tribe.id });
});

app.delete('/tribes/leave', requireAuth, (req, res) => {
  const membership = db.prepare('SELECT tribe_id FROM tribe_members WHERE user_id = ?').get(req.user.id);
  if (!membership) {
    return res.status(404).json({ error: 'You are not in a tribe.' });
  }

  const tribe = db.prepare('SELECT id, name, leader_user_id FROM tribes WHERE id = ?').get(membership.tribe_id);
  if (!tribe) return res.status(404).json({ error: 'Tribe not found.' });

  const memberCount = db.prepare('SELECT COUNT(*) AS cnt FROM tribe_members WHERE tribe_id = ?').get(tribe.id);

  if (tribe.leader_user_id === req.user.id && memberCount.cnt > 1) {
    return res.status(400).json({ error: 'You are the tribe leader. Transfer leadership or disband the tribe before leaving.' });
  }

  const leaveOrDisband = db.transaction(() => {
    db.prepare('DELETE FROM tribe_members WHERE user_id = ?').run(req.user.id);
    if (memberCount.cnt === 1) {
      db.prepare('DELETE FROM tribes WHERE id = ?').run(tribe.id);
    }
  });

  leaveOrDisband();
  res.json({ ok: true });
});

app.get('/tribes/leaderboard', requireAuth, (req, res) => {
  const membership = db.prepare('SELECT tribe_id FROM tribe_members WHERE user_id = ?').get(req.user.id);
  if (!membership) return res.status(403).json({ error: 'You are not in a tribe.' });

  const rows = db.prepare(`
    SELECT u.username,
           COUNT(CASE WHEN c.memorized = 1 THEN 1 END) AS memorized_count
    FROM tribe_members tm
    JOIN users u ON u.id = tm.user_id
    LEFT JOIN cards c ON c.user_id = tm.user_id
    WHERE tm.tribe_id = ?
    GROUP BY tm.user_id
    ORDER BY memorized_count DESC
  `).all(membership.tribe_id);

  res.json(rows);
});

// ── Start ──────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Don't Forget! Bible running on port ${PORT}`);
});
