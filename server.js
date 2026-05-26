require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-secret-change-me';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const PROD = process.env.NODE_ENV === 'production';
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const PAYMENT_INFO = {
  whish: { number: process.env.WHISH_NUMBER || '+961 XX XXX XXX', name: process.env.WHISH_NAME || '' },
  omt:   { number: process.env.OMT_NUMBER   || '+961 XX XXX XXX', name: process.env.OMT_NAME   || '' }
};

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ─── DATABASE ───────────────────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'bond.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  phone TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS therapists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  first_name TEXT,
  last_name TEXT,
  title_prefix TEXT,
  gender TEXT,
  phone TEXT,
  city TEXT,
  address TEXT,
  bio TEXT,
  languages TEXT,
  specialty TEXT,
  experience TEXT,
  license TEXT,
  licensing_body TEXT,
  university TEXT,
  grad_year TEXT,
  focus TEXT,
  approaches TEXT,
  session_types TEXT,
  working_days TEXT,
  start_time TEXT,
  end_time TEXT,
  duration TEXT,
  status_availability TEXT,
  online_price TEXT,
  onsite_price TEXT,
  pay_methods TEXT,
  insurance TEXT,
  cancellation TEXT,
  schedule_notes TEXT,
  pricing_notes TEXT,
  website TEXT,
  cv_filename TEXT,
  photo_filename TEXT,
  cert_filenames TEXT,
  status TEXT DEFAULT 'pending',
  submitted_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  therapist_name TEXT,
  therapist_specialty TEXT,
  therapist_city TEXT,
  time_slot TEXT,
  session_type TEXT,
  total INTEGER DEFAULT 60,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_name TEXT,
  last_name TEXT,
  email TEXT,
  phone TEXT,
  message TEXT,
  is_read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  approved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  booking_id INTEGER UNIQUE,
  client_id INTEGER NOT NULL,
  therapist_id INTEGER NOT NULL,
  rating INTEGER NOT NULL,
  comment TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (client_id) REFERENCES clients(id),
  FOREIGN KEY (therapist_id) REFERENCES therapists(id)
);

CREATE TABLE IF NOT EXISTS blog_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  excerpt TEXT,
  content TEXT,
  author TEXT,
  published INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
`);

// ─── MIGRATIONS (idempotent column adds for existing DBs) ───────────────────
function ensureColumn(table, col, def) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.find(c => c.name === col)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
  }
}
ensureColumn('therapists', 'password_hash', 'TEXT');
ensureColumn('bookings', 'therapist_id', 'INTEGER');
ensureColumn('bookings', 'appointment_date', 'TEXT');
ensureColumn('bookings', 'payment_method', 'TEXT');
ensureColumn('bookings', 'payment_ref', 'TEXT');
ensureColumn('bookings', 'payment_status', "TEXT DEFAULT 'unpaid'");
ensureColumn('bookings', 'payment_submitted_at', 'TEXT');

// Prevent two active bookings for the same therapist/date/time
db.exec(`
CREATE UNIQUE INDEX IF NOT EXISTS idx_bookings_slot
ON bookings(therapist_id, appointment_date, time_slot)
WHERE therapist_id IS NOT NULL AND status != 'cancelled';
`);

// ─── APP ────────────────────────────────────────────────────────────────────
const app = express();
if (PROD) app.set('trust proxy', 1); // honour X-Forwarded-* behind a reverse proxy (Render/Railway/etc)
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: PROD,                       // requires HTTPS in production
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

// ─── RATE LIMITERS ──────────────────────────────────────────────────────────
const loginLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,  standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });
const signupLimiter  = rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });
const contactLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5,   standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });
const bookingLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20,  standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });
const therapistSignupLimiter = rateLimit({ windowMs: 24 * 60 * 60 * 1000, max: 3, standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });
const forgotLimiter  = rateLimit({ windowMs: 60 * 60 * 1000, max: 3,   standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_attempts' } });

// ─── FILE UPLOADS ───────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e6)}-${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 12 * 1024 * 1024 }
});

// ─── HELPERS ────────────────────────────────────────────────────────────────
function requireClient(req, res, next) {
  if (!req.session.clientId) return res.status(401).json({ error: 'login_required' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'admin_required' });
  next();
}
function requireTherapist(req, res, next) {
  if (!req.session.therapistId) return res.status(401).json({ error: 'login_required' });
  next();
}
function parseList(s) { try { return s ? JSON.parse(s) : []; } catch { return []; } }

// ─── STATIC PAGES ───────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(ROOT, 'mainweb.html')));
app.get('/therapist', (req, res) => res.sendFile(path.join(ROOT, 'subwebt.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(ROOT, 'public', 'admin.html')));
app.get('/therapist-portal', (req, res) => res.sendFile(path.join(ROOT, 'public', 'therapist-portal.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(ROOT, 'public', 'privacy.html')));
app.get('/terms',   (req, res) => res.sendFile(path.join(ROOT, 'public', 'terms.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(ROOT, 'public', 'reset-password.html')));
app.get(/^\/(blog|about)(\/.*)?$/, (req, res) => res.sendFile(path.join(ROOT, 'mainweb.html')));

// Serve original files at their old paths so existing links keep working
app.get('/mainweb.html', (req, res) => res.sendFile(path.join(ROOT, 'mainweb.html')));
app.get('/subwebt.html', (req, res) => res.sendFile(path.join(ROOT, 'subwebt.html')));

app.use('/public', express.static(path.join(ROOT, 'public'), {
  maxAge: '7d',
  setHeaders: (res, p) => {
    if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

// ─── CLIENT AUTH ────────────────────────────────────────────────────────────
app.post('/api/clients/signup', signupLimiter, (req, res) => {
  const { email, password, firstName, lastName, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
  if (password.length < 6) return res.status(400).json({ error: 'password_too_short' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare(`INSERT INTO clients (email, password_hash, first_name, last_name, phone) VALUES (?, ?, ?, ?, ?)`);
    const info = stmt.run(email.toLowerCase().trim(), hash, firstName || '', lastName || '', phone || '');
    req.session.clientId = info.lastInsertRowid;
    req.session.clientEmail = email.toLowerCase().trim();
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'email_already_registered' });
    res.status(500).json({ error: 'signup_failed' });
  }
});

app.post('/api/clients/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
  const row = db.prepare(`SELECT * FROM clients WHERE email = ?`).get(email.toLowerCase().trim());
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  req.session.clientId = row.id;
  req.session.clientEmail = row.email;
  res.json({ ok: true, id: row.id, firstName: row.first_name, email: row.email });
});

app.post('/api/clients/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ─── PASSWORD RESET (client) ────────────────────────────────────────────────
const crypto = require('crypto');

// Request a reset — always returns ok (don't leak which emails exist)
app.post('/api/clients/forgot-password', forgotLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.json({ ok: true });
  const client = db.prepare(`SELECT id FROM clients WHERE email = ?`).get(String(email).toLowerCase().trim());
  if (client) {
    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`INSERT INTO password_resets (client_id, token, expires_at) VALUES (?, ?, ?)`)
      .run(client.id, token, expiresAt);
    // When SMTP is wired up later, email the link here:
    // sendEmail(email, `${PUBLIC_URL}/reset-password?token=${token}`);
  }
  res.json({ ok: true });
});

// Validate token (for the reset page)
app.get('/api/clients/reset-password/check', (req, res) => {
  const { token } = req.query;
  if (!token) return res.json({ valid: false });
  const row = db.prepare(`SELECT pr.*, c.email FROM password_resets pr JOIN clients c ON c.id = pr.client_id WHERE pr.token = ?`).get(token);
  if (!row || row.used || new Date(row.expires_at) < new Date() || !row.approved) {
    return res.json({ valid: false });
  }
  res.json({ valid: true, email: row.email });
});

// Apply the new password
app.post('/api/clients/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'password_too_short' });
  const row = db.prepare(`SELECT * FROM password_resets WHERE token = ?`).get(token);
  if (!row || row.used || !row.approved || new Date(row.expires_at) < new Date()) {
    return res.status(400).json({ error: 'invalid_or_expired' });
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`UPDATE clients SET password_hash = ? WHERE id = ?`).run(hash, row.client_id);
  db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).run(row.id);
  res.json({ ok: true });
});

// Admin: list + approve pending resets
app.get('/api/admin/password-resets', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT pr.*, c.email AS client_email, c.first_name AS client_first_name, c.last_name AS client_last_name
    FROM password_resets pr LEFT JOIN clients c ON c.id = pr.client_id
    WHERE pr.used = 0 AND pr.expires_at > datetime('now')
    ORDER BY pr.id DESC
  `).all();
  res.json(rows);
});

app.post('/api/admin/password-resets/:id/approve', requireAdmin, (req, res) => {
  const row = db.prepare(`SELECT * FROM password_resets WHERE id = ?`).get(req.params.id);
  if (!row || row.used) return res.status(404).json({ error: 'not_found' });
  db.prepare(`UPDATE password_resets SET approved = 1 WHERE id = ?`).run(req.params.id);
  res.json({ ok: true, link: `${PUBLIC_URL}/reset-password?token=${row.token}` });
});

app.post('/api/admin/password-resets/:id/dismiss', requireAdmin, (req, res) => {
  db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/clients/me', (req, res) => {
  if (!req.session.clientId) return res.json({ loggedIn: false });
  const row = db.prepare(`SELECT id, email, first_name, last_name, phone FROM clients WHERE id = ?`).get(req.session.clientId);
  if (!row) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, id: row.id, email: row.email, firstName: row.first_name, lastName: row.last_name, phone: row.phone });
});

// ─── BOOKINGS ───────────────────────────────────────────────────────────────
app.post('/api/bookings', bookingLimiter, requireClient, (req, res) => {
  const { therapistId, therapistName, therapistSpecialty, therapistCity, timeSlot, sessionType, appointmentDate, total } = req.body || {};
  if (!therapistId || !therapistName || !timeSlot || !sessionType || !appointmentDate) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate)) {
    return res.status(400).json({ error: 'invalid_date' });
  }
  // Don't allow booking in the past
  const today = new Date(); today.setHours(0,0,0,0);
  const d = new Date(appointmentDate + 'T00:00:00');
  if (d < today) return res.status(400).json({ error: 'date_in_past' });

  try {
    const info = db.prepare(`
      INSERT INTO bookings (client_id, therapist_id, therapist_name, therapist_specialty, therapist_city, appointment_date, time_slot, session_type, total)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.session.clientId,
      therapistId,
      therapistName,
      therapistSpecialty || '',
      therapistCity || '',
      appointmentDate,
      timeSlot,
      sessionType,
      total || 60
    );
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'slot_taken' });
    }
    console.error(e);
    res.status(500).json({ error: 'booking_failed' });
  }
});

// Time slots already booked for a therapist on a date (for the booking UI)
app.get('/api/therapists/:id/booked-slots', (req, res) => {
  const date = req.query.date;
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'invalid_date' });
  const rows = db.prepare(`
    SELECT time_slot FROM bookings
    WHERE therapist_id = ? AND appointment_date = ? AND status != 'cancelled'
  `).all(req.params.id, date);
  res.json(rows.map(r => r.time_slot));
});

// Client's own bookings (+ payment + review state)
app.get('/api/clients/me/bookings', requireClient, (req, res) => {
  const rows = db.prepare(`
    SELECT b.id, b.therapist_id, b.therapist_name, b.therapist_specialty, b.therapist_city,
           b.appointment_date, b.time_slot, b.session_type, b.total, b.status, b.created_at,
           b.payment_method, b.payment_status, b.payment_ref,
           (SELECT id FROM reviews WHERE booking_id = b.id) AS review_id
    FROM bookings b WHERE b.client_id = ?
    ORDER BY b.appointment_date DESC, b.id DESC
  `).all(req.session.clientId);
  res.json(rows);
});

// Cancel own booking
app.post('/api/clients/me/bookings/:id/cancel', requireClient, (req, res) => {
  db.prepare(`UPDATE bookings SET status = 'cancelled' WHERE id = ? AND client_id = ?`)
    .run(req.params.id, req.session.clientId);
  res.json({ ok: true });
});

// Public payment info (Whish / OMT details to show on payment screen)
app.get('/api/payment-info', (req, res) => {
  res.json(PAYMENT_INFO);
});

// Client submits payment reference for a booking
app.post('/api/clients/me/bookings/:id/payment', requireClient, (req, res) => {
  const { method, ref } = req.body || {};
  if (!['whish','omt'].includes(method)) return res.status(400).json({ error: 'invalid_method' });
  if (!ref || !ref.trim()) return res.status(400).json({ error: 'missing_ref' });
  const r = db.prepare(`SELECT id FROM bookings WHERE id = ? AND client_id = ?`).get(req.params.id, req.session.clientId);
  if (!r) return res.status(404).json({ error: 'not_found' });
  db.prepare(`
    UPDATE bookings
    SET payment_method = ?, payment_ref = ?, payment_status = 'pending_review', payment_submitted_at = datetime('now')
    WHERE id = ?
  `).run(method, ref.trim().slice(0, 80), req.params.id);
  res.json({ ok: true });
});

// Admin: confirm or decline a payment
app.post('/api/admin/bookings/:id/payment/:action', requireAdmin, (req, res) => {
  const { action } = req.params;
  if (!['confirm','decline'].includes(action)) return res.status(400).json({ error: 'invalid_action' });
  const newStatus = action === 'confirm' ? 'confirmed' : 'declined';
  const newBookingStatus = action === 'confirm' ? 'confirmed' : 'pending';
  db.prepare(`UPDATE bookings SET payment_status = ?, status = ? WHERE id = ?`).run(newStatus, newBookingStatus, req.params.id);
  res.json({ ok: true });
});

// Filter options for the directory (only from approved therapists)
app.get('/api/filters/options', (req, res) => {
  const cities = db.prepare(`SELECT DISTINCT city FROM therapists WHERE status = 'approved' AND city <> '' ORDER BY city`).all().map(r => r.city);
  const specialties = db.prepare(`SELECT DISTINCT specialty FROM therapists WHERE status = 'approved' AND specialty <> '' ORDER BY specialty`).all().map(r => r.specialty);
  res.json({ cities, specialties });
});

// ─── BLOG ───────────────────────────────────────────────────────────────────
function slugify(s) {
  return String(s).toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

// Public: list published posts
app.get('/api/blog', (req, res) => {
  const rows = db.prepare(`SELECT id, slug, title, excerpt, author, created_at FROM blog_posts WHERE published = 1 ORDER BY id DESC`).all();
  res.json(rows);
});

// Public: read single post by slug
app.get('/api/blog/:slug', (req, res) => {
  const r = db.prepare(`SELECT id, slug, title, excerpt, content, author, created_at, updated_at FROM blog_posts WHERE slug = ? AND published = 1`).get(req.params.slug);
  if (!r) return res.status(404).json({ error: 'not_found' });
  res.json(r);
});

// Admin: full list including drafts
app.get('/api/admin/blog', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM blog_posts ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/admin/blog', requireAdmin, (req, res) => {
  const { title, excerpt, content, author, published } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'missing_fields' });
  let slug = slugify(title);
  // ensure unique
  let n = 1;
  while (db.prepare(`SELECT id FROM blog_posts WHERE slug = ?`).get(slug)) {
    slug = slugify(title) + '-' + (++n);
  }
  const info = db.prepare(`
    INSERT INTO blog_posts (slug, title, excerpt, content, author, published)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(slug, title, excerpt || '', content, author || '', published ? 1 : 0);
  res.json({ ok: true, id: info.lastInsertRowid, slug });
});

app.put('/api/admin/blog/:id', requireAdmin, (req, res) => {
  const { title, excerpt, content, author, published } = req.body || {};
  const existing = db.prepare(`SELECT * FROM blog_posts WHERE id = ?`).get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not_found' });
  db.prepare(`
    UPDATE blog_posts
    SET title = ?, excerpt = ?, content = ?, author = ?, published = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(
    title || existing.title,
    excerpt !== undefined ? excerpt : existing.excerpt,
    content || existing.content,
    author !== undefined ? author : existing.author,
    published ? 1 : 0,
    req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/admin/blog/:id', requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM blog_posts WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

// ─── CONTACT MESSAGES ───────────────────────────────────────────────────────
app.post('/api/messages', contactLimiter, (req, res) => {
  const { firstName, lastName, email, phone, message } = req.body || {};
  if (!firstName || !email || !message) return res.status(400).json({ error: 'missing_fields' });
  db.prepare(`INSERT INTO messages (first_name, last_name, email, phone, message) VALUES (?, ?, ?, ?, ?)`)
    .run(firstName, lastName || '', email, phone || '', message);
  res.json({ ok: true });
});

// ─── THERAPIST SIGNUP ───────────────────────────────────────────────────────
app.post('/api/therapists/signup',
  therapistSignupLimiter,
  upload.fields([
    { name: 'cv', maxCount: 1 },
    { name: 'photo', maxCount: 1 },
    { name: 'certificates', maxCount: 10 }
  ]),
  (req, res) => {
    try {
      const b = req.body;
      const cv = req.files?.cv?.[0];
      const photo = req.files?.photo?.[0];
      const certs = req.files?.certificates || [];

      if (!b.email || !b.firstName || !b.lastName || !b.password) {
        return res.status(400).json({ error: 'missing_required_fields' });
      }
      if (b.password.length < 6) {
        return res.status(400).json({ error: 'password_too_short' });
      }
      const passwordHash = bcrypt.hashSync(b.password, 10);

      const info = db.prepare(`
        INSERT INTO therapists (
          email, password_hash, first_name, last_name, title_prefix, gender, phone, city, address, bio,
          languages, specialty, experience, license, licensing_body, university, grad_year,
          focus, approaches, session_types, working_days, start_time, end_time, duration,
          status_availability, online_price, onsite_price, pay_methods, insurance,
          cancellation, schedule_notes, pricing_notes, website,
          cv_filename, photo_filename, cert_filenames, status
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?, 'pending'
        )
      `).run(
        (b.email || '').toLowerCase().trim(), passwordHash, b.firstName, b.lastName, b.titlePrefix || '', b.gender || '',
        b.phone || '', b.city || '', b.address || '', b.bio || '',
        b.languages || '[]', b.specialty || '', b.experience || '', b.license || '',
        b.licensingBody || '', b.university || '', b.gradYear || '',
        b.focus || '[]', b.approaches || '[]', b.sessionTypes || '[]', b.workingDays || '[]',
        b.startTime || '', b.endTime || '', b.duration || '',
        b.statusAvailability || '', b.onlinePrice || '', b.onsitePrice || '',
        b.payMethods || '[]', b.insurance || '',
        b.cancellation || '', b.scheduleNotes || '', b.pricingNotes || '', b.website || '',
        cv ? cv.filename : null,
        photo ? photo.filename : null,
        JSON.stringify(certs.map(f => f.filename))
      );
      // Auto-login the therapist so they can track their application
      req.session.therapistId = info.lastInsertRowid;
      res.json({ ok: true, id: info.lastInsertRowid });
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) {
        return res.status(409).json({ error: 'email_already_applied' });
      }
      console.error(e);
      res.status(500).json({ error: 'signup_failed' });
    }
  }
);

// ─── THERAPIST AUTH ─────────────────────────────────────────────────────────
app.post('/api/therapists/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
  const row = db.prepare(`SELECT id, email, password_hash, status FROM therapists WHERE email = ?`).get(email.toLowerCase().trim());
  if (!row || !row.password_hash || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  req.session.therapistId = row.id;
  res.json({ ok: true, id: row.id, status: row.status });
});

app.post('/api/therapists/logout', (req, res) => {
  req.session.therapistId = null;
  res.json({ ok: true });
});

app.get('/api/therapists/me', (req, res) => {
  if (!req.session.therapistId) return res.json({ loggedIn: false });
  const r = db.prepare(`SELECT id, email, first_name, last_name, title_prefix, specialty, city, status, online_price, onsite_price FROM therapists WHERE id = ?`).get(req.session.therapistId);
  if (!r) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, ...r });
});

app.get('/api/therapists/me/bookings', requireTherapist, (req, res) => {
  const rows = db.prepare(`
    SELECT b.id, b.appointment_date, b.time_slot, b.session_type, b.total, b.status, b.created_at,
           c.first_name AS client_first_name, c.last_name AS client_last_name, c.email AS client_email, c.phone AS client_phone
    FROM bookings b LEFT JOIN clients c ON c.id = b.client_id
    WHERE b.therapist_id = ?
    ORDER BY b.appointment_date DESC, b.id DESC
  `).all(req.session.therapistId);
  res.json(rows);
});

// ─── PUBLIC THERAPIST DIRECTORY (approved only) ─────────────────────────────
function therapistAggregates(id) {
  const r = db.prepare(`SELECT AVG(rating) AS avg, COUNT(*) AS n FROM reviews WHERE therapist_id = ?`).get(id);
  return { rating: r.avg ? Math.round(r.avg * 10) / 10 : null, reviews: r.n || 0 };
}

app.get('/api/therapists/public', (req, res) => {
  const rows = db.prepare(`
    SELECT id, title_prefix, first_name, last_name, specialty, city, bio, languages,
           online_price, onsite_price, session_types, focus, approaches, insurance, photo_filename
    FROM therapists WHERE status = 'approved' ORDER BY id DESC
  `).all();
  res.json(rows.map(r => {
    const agg = therapistAggregates(r.id);
    return {
      id: r.id,
      name: `${r.title_prefix || ''} ${r.first_name} ${r.last_name}`.trim(),
      specialty: r.specialty,
      city: r.city,
      bio: r.bio,
      languages: parseList(r.languages),
      focus: parseList(r.focus),
      approaches: parseList(r.approaches),
      insurance: r.insurance || '',
      onlinePrice: r.online_price,
      onsitePrice: r.onsite_price,
      sessionTypes: parseList(r.session_types),
      hasPhoto: !!r.photo_filename,
      rating: agg.rating,
      reviewCount: agg.reviews
    };
  }));
});

// Full public profile for the detail page
app.get('/api/therapists/:id/public', (req, res) => {
  const r = db.prepare(`
    SELECT id, title_prefix, first_name, last_name, specialty, city, bio, languages,
           focus, approaches, online_price, onsite_price, session_types,
           insurance, cancellation, duration, working_days, start_time, end_time,
           experience, university, photo_filename, website
    FROM therapists WHERE id = ? AND status = 'approved'
  `).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'not_found' });
  const agg = therapistAggregates(r.id);
  res.json({
    id: r.id,
    name: `${r.title_prefix || ''} ${r.first_name} ${r.last_name}`.trim(),
    specialty: r.specialty,
    city: r.city,
    bio: r.bio,
    languages: parseList(r.languages),
    focus: parseList(r.focus),
    approaches: parseList(r.approaches),
    sessionTypes: parseList(r.session_types),
    workingDays: parseList(r.working_days),
    onlinePrice: r.online_price,
    onsitePrice: r.onsite_price,
    insurance: r.insurance,
    cancellation: r.cancellation,
    duration: r.duration,
    startTime: r.start_time,
    endTime: r.end_time,
    experience: r.experience,
    university: r.university,
    website: r.website,
    hasPhoto: !!r.photo_filename,
    rating: agg.rating,
    reviewCount: agg.reviews
  });
});

// Public photo of an approved therapist
app.get('/api/therapists/:id/photo', (req, res) => {
  const r = db.prepare(`SELECT photo_filename, status FROM therapists WHERE id = ?`).get(req.params.id);
  if (!r || r.status !== 'approved' || !r.photo_filename) return res.status(404).send('Not found');
  const filePath = path.join(UPLOAD_DIR, path.basename(r.photo_filename));
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.sendFile(filePath);
});

// Public reviews
app.get('/api/therapists/:id/reviews', (req, res) => {
  const rows = db.prepare(`
    SELECT r.rating, r.comment, r.created_at, c.first_name AS client_first_name
    FROM reviews r JOIN clients c ON c.id = r.client_id
    WHERE r.therapist_id = ?
    ORDER BY r.id DESC
    LIMIT 50
  `).all(req.params.id);
  res.json(rows);
});

// Submit a review (client must own a paid/confirmed booking for that therapist)
app.post('/api/reviews', requireClient, (req, res) => {
  const { bookingId, rating, comment } = req.body || {};
  const r = Number(rating);
  if (!bookingId || !r || r < 1 || r > 5) return res.status(400).json({ error: 'invalid_input' });
  const booking = db.prepare(`SELECT * FROM bookings WHERE id = ? AND client_id = ?`).get(bookingId, req.session.clientId);
  if (!booking) return res.status(404).json({ error: 'booking_not_found' });
  if (booking.status === 'cancelled') return res.status(400).json({ error: 'cannot_review_cancelled' });
  const exists = db.prepare(`SELECT id FROM reviews WHERE booking_id = ?`).get(bookingId);
  if (exists) return res.status(409).json({ error: 'already_reviewed' });
  db.prepare(`INSERT INTO reviews (booking_id, client_id, therapist_id, rating, comment) VALUES (?, ?, ?, ?, ?)`)
    .run(bookingId, req.session.clientId, booking.therapist_id, r, (comment || '').slice(0, 1000));
  res.json({ ok: true });
});

// ─── ADMIN AUTH ─────────────────────────────────────────────────────────────
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'invalid_credentials' });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.json({ ok: true });
});

app.get('/api/admin/me', (req, res) => {
  res.json({ loggedIn: !!req.session.isAdmin });
});

// ─── ADMIN DATA ─────────────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  res.json({
    bookings: db.prepare(`SELECT COUNT(*) AS c FROM bookings`).get().c,
    messages: db.prepare(`SELECT COUNT(*) AS c FROM messages`).get().c,
    unreadMessages: db.prepare(`SELECT COUNT(*) AS c FROM messages WHERE is_read = 0`).get().c,
    pendingTherapists: db.prepare(`SELECT COUNT(*) AS c FROM therapists WHERE status = 'pending'`).get().c,
    approvedTherapists: db.prepare(`SELECT COUNT(*) AS c FROM therapists WHERE status = 'approved'`).get().c,
    clients: db.prepare(`SELECT COUNT(*) AS c FROM clients`).get().c,
    pendingResets: db.prepare(`SELECT COUNT(*) AS c FROM password_resets WHERE used = 0 AND approved = 0 AND expires_at > datetime('now')`).get().c
  });
});

app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT b.*, c.email AS client_email, c.first_name AS client_first_name,
           c.last_name AS client_last_name, c.phone AS client_phone
    FROM bookings b
    LEFT JOIN clients c ON c.id = b.client_id
    ORDER BY b.id DESC
  `).all();
  res.json(rows);
});

app.get('/api/admin/messages', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM messages ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/admin/messages/:id/read', requireAdmin, (req, res) => {
  db.prepare(`UPDATE messages SET is_read = 1 WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/messages/:id', requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM messages WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/therapists', requireAdmin, (req, res) => {
  const status = req.query.status;
  const rows = status
    ? db.prepare(`SELECT * FROM therapists WHERE status = ? ORDER BY id DESC`).all(status)
    : db.prepare(`SELECT * FROM therapists ORDER BY id DESC`).all();
  res.json(rows.map(r => ({
    ...r,
    languages: parseList(r.languages),
    focus: parseList(r.focus),
    approaches: parseList(r.approaches),
    session_types: parseList(r.session_types),
    working_days: parseList(r.working_days),
    pay_methods: parseList(r.pay_methods),
    cert_filenames: parseList(r.cert_filenames)
  })));
});

app.post('/api/admin/therapists/:id/approve', requireAdmin, (req, res) => {
  db.prepare(`UPDATE therapists SET status = 'approved' WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/therapists/:id/decline', requireAdmin, (req, res) => {
  db.prepare(`UPDATE therapists SET status = 'declined' WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/therapists/:id', requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM therapists WHERE id = ?`).run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/clients', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, email, first_name, last_name, phone, created_at FROM clients ORDER BY id DESC`).all();
  res.json(rows);
});

// Reset a client's password — returns a one-time temp password the admin can share
app.post('/api/admin/clients/:id/reset-password', requireAdmin, (req, res) => {
  const row = db.prepare(`SELECT id FROM clients WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const temp = Math.random().toString(36).slice(-10) + 'A1!';
  db.prepare(`UPDATE clients SET password_hash = ? WHERE id = ?`).run(bcrypt.hashSync(temp, 10), req.params.id);
  res.json({ ok: true, tempPassword: temp });
});

// Serve uploaded files (CVs, photos, certs) only when admin is logged in
app.get('/api/admin/file/:filename', requireAdmin, (req, res) => {
  const filename = path.basename(req.params.filename);
  const full = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(full)) return res.status(404).send('Not found');
  res.sendFile(full);
});

// ─── DAILY DB BACKUP ────────────────────────────────────────────────────────
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
fs.mkdirSync(BACKUP_DIR, { recursive: true });

async function runBackup() {
  try {
    const stamp = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dest = path.join(BACKUP_DIR, `bond-${stamp}.db`);
    // Use SQLite's online backup API for a consistent snapshot, even mid-write
    await db.backup(dest);
    // Keep last 14 backups
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('bond-') && f.endsWith('.db'))
      .sort();
    while (files.length > 14) {
      const oldest = files.shift();
      try { fs.unlinkSync(path.join(BACKUP_DIR, oldest)); } catch {}
    }
    console.log(`💾 DB backup written: ${path.basename(dest)} (${files.length} kept)`);
  } catch (e) {
    console.error('Backup failed:', e.message);
  }
}

function scheduleDailyBackup() {
  const now = new Date();
  const next = new Date(now);
  next.setHours(3, 0, 0, 0); // 3:00 AM local
  if (next <= now) next.setDate(next.getDate() + 1);
  const delay = next - now;
  setTimeout(() => {
    runBackup();
    setInterval(runBackup, 24 * 60 * 60 * 1000);
  }, delay);
  console.log(`   Backups:    daily at 03:00 → ${BACKUP_DIR}`);
}

// Backup once on startup if today's snapshot doesn't exist yet
(() => {
  const todayFile = path.join(BACKUP_DIR, `bond-${new Date().toISOString().slice(0, 10)}.db`);
  if (!fs.existsSync(todayFile)) runBackup();
  scheduleDailyBackup();
})();

// ─── START ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🌿 Bond Therapy server running on http://localhost:${PORT}`);
  console.log(`   Main site:  http://localhost:${PORT}/`);
  console.log(`   Therapist:  http://localhost:${PORT}/therapist`);
  console.log(`   Admin:      http://localhost:${PORT}/admin`);
  console.log(`   Admin user: ${ADMIN_USER}`);
  if (!process.env.ADMIN_PASS) {
    console.log(`   ⚠  Using default admin password — set ADMIN_PASS in .env!`);
  }
  console.log('');
});
