// server.js
import 'dotenv/config';
import path from 'path';
import fs from 'fs';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';
import multer from 'multer';
import mime from 'mime';
import { nanoid } from 'nanoid';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { fileURLToPath } from 'url';

let bcrypt;
try { bcrypt = (await import('bcrypt')).default; }
catch { bcrypt = (await import('bcryptjs')).default; }

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// DB path – free tier friendly
const isRender = !!process.env.RENDER;
const DEFAULT_DB_FILE = isRender ? '/tmp/app.db' : path.join(__dirname, 'data', 'app.db');
const DB_FILE  = process.env.DB_FILE || DEFAULT_DB_FILE;
const SESSION_DB = DB_FILE.startsWith('/tmp')
  ? '/tmp/sessions.db'
  : path.join(path.dirname(DB_FILE), 'sessions.db');

// Folders
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!DB_FILE.startsWith('/tmp')) fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

// ---------- App ----------
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

// Security (nới CSP cho EJS/inline)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// Static
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '7d', etag: true }));
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', etag: true }));

// Parsers
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json());

// Rate limit
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 300,
}));

// Sessions (SQLite store)
const SQLiteStore = connectSqlite3(session);
app.use(session({
  store: new SQLiteStore({ db: path.basename(SESSION_DB), dir: path.dirname(SESSION_DB) }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!process.env.RENDER, // secure cookie khi chạy trên Render (https)
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 ngày
  }
}));

// Helper: expose current user to views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// ---------- DB init ----------
let db;
async function initDb() {
  const openWith = async (file) => {
    const conn = await open({ filename: file, driver: sqlite3.Database });
    await conn.exec(`PRAGMA journal_mode = WAL;`);
    await conn.exec(`
      CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        image_path TEXT NOT NULL,
        start_price REAL NOT NULL CHECK(start_price >= 0),
        min_increment REAL NOT NULL DEFAULT 1,
        end_time DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status TEXT NOT NULL DEFAULT 'active',
        owner_id INTEGER
      );

      CREATE TABLE IF NOT EXISTS bids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id TEXT NOT NULL,
        bidder TEXT,
        amount REAL NOT NULL CHECK(amount > 0),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES items(id)
      );
      CREATE INDEX IF NOT EXISTS idx_bids_item ON bids(item_id);

      CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        role TEXT NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      /* nhiều ảnh / item */
      CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id TEXT NOT NULL,
        image_path TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES items(id)
      );
      CREATE INDEX IF NOT EXISTS idx_images_item ON images(item_id, sort_order);
    `);
    return conn;
  };

  try {
    db = await openWith(DB_FILE);
    console.log('✅ Using SQLite at:', DB_FILE);
  } catch (err) {
    console.error('DB open failed at', DB_FILE, err.code, err.message);
    const fallback = '/tmp/app.db';
    if (DB_FILE !== fallback) {
      db = await openWith(fallback);
      console.log('↩︎ Fallback SQLite at:', fallback);
    } else {
      throw err;
    }
  }

  // seed admin
  const adminEmail = 'admin@site.local';
  const admin = await db.get('SELECT id FROM users WHERE email=?', adminEmail);
  if (!admin) {
    const hash = await bcrypt.hash('admin123', 10);
    await db.run(
      'INSERT INTO users(email, password_hash, display_name, verified, role) VALUES(?,?,?,?,?)',
      adminEmail, hash, 'Administrator', 1, 'admin'
    );
    console.log('👑 Seeded admin: admin@site.local / admin123');
  }
}

// ---------- Multer (uploads) ----------
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, UPLOAD_DIR); },
  filename: function (req, file, cb) {
    const ext = mime.getExtension(file.mimetype) || 'bin';
    cb(null, `${Date.now()}_${nanoid(6)}.${ext}`);
  }
});
function imageFilter(req, file, cb) {
  if (/^image\//.test(file.mimetype)) cb(null, true);
  else cb(new Error('File phải là ảnh'), false);
}
const upload = multer({ storage, fileFilter: imageFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// ---------- Auth helpers ----------
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

function requireAdmin(req, res, next) {
  const byKey = req.query.key && req.query.key === ADMIN_KEY;
  const bySession = req.session.user && req.session.user.role === 'admin';
  if (byKey || bySession) return next();
  return res.status(403).send('Forbidden');
}

// ---------- Utils ----------
function computeEnded(row) {
  const endedByStatus = row.status && row.status !== 'active';
  const endedByTime = row.end_time ? (Date.now() > new Date(row.end_time).getTime()) : false;
  return endedByStatus || endedByTime;
}
async function enrichItem(row) {
  const agg = await db.get(
    `SELECT COUNT(*) as bidCount, MAX(amount) as topBid
     FROM bids WHERE item_id = ?`, row.id);
  return {
    ...row,
    bidCount: agg?.bidCount || 0,
    topBid: agg?.topBid || null,
    ended: computeEnded(row),
  };
}

// ---------- Routes ----------

// Home (gallery + search)
app.get('/', async (req, res, next) => {
  try {
    const q = (req.query.q || '').trim();
    const where = [];
    const params = [];
    if (q) {
      where.push('(i.title LIKE ? OR i.description LIKE ?)');
      params.push(`%${q}%`, `%${q}%`);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const items = await db.all(
      `SELECT i.* FROM items i ${whereSql} ORDER BY i.created_at DESC LIMIT 100`, params
    );
    const full = await Promise.all(items.map(enrichItem));
    res.render('index', { items: full, q });
  } catch (e) { next(e); }
});

// Item detail
app.get('/item/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const item = await db.get('SELECT * FROM items WHERE id=?', id);
    if (!item) return res.status(404).render('404');
    const images = await db.all(
      'SELECT * FROM images WHERE item_id=? ORDER BY sort_order, id', id
    );
    const gallery = images.length ? images.map(i => i.image_path) : [item.image_path];
    const owner = item.owner_id
      ? await db.get('SELECT id, display_name, verified, role FROM users WHERE id=?', item.owner_id)
      : null;
    const bids = await db.all('SELECT bidder, amount FROM bids WHERE item_id=? ORDER BY amount DESC', id);
    const full = await enrichItem(item);
    res.render('item', {
      item: full,
      gallery,
      imagesFull: images,
      owner,
      bids
    });
  } catch (e) { next(e); }
});

// Place bid
app.post('/item/:id/bid', async (req, res, next) => {
  try {
    const id = req.params.id;
    const bidder = (req.body.bidder || '').trim().slice(0, 60);
    const amount = parseFloat(req.body.amount);
    const item = await db.get('SELECT * FROM items WHERE id=?', id);
    if (!item) return res.status(404).send('Item not found');
    if (computeEnded(item) || item.status !== 'active') {
      return res.status(400).send('Phiên đấu giá đã kết thúc.');
    }
    const agg = await db.get(
      'SELECT COALESCE(MAX(amount), 0) as topBid FROM bids WHERE item_id=?', id
    );
    const minBase = Math.max(agg?.topBid || 0, item.start_price);
    const minReq = minBase + (item.min_increment || 1);
    if (!Number.isFinite(amount) || amount < minReq) {
      throw new Error(`Bid must be at least ${minReq.toFixed(2)}`);
    }
    await db.run(
      'INSERT INTO bids(item_id, bidder, amount) VALUES(?,?,?)',
      id, bidder || 'Ẩn danh', amount
    );
    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// Close auction (admin)
app.post('/item/:id/close', requireAdmin, async (req, res, next) => {
  try {
    await db.run('UPDATE items SET status=? WHERE id=?', 'ended', req.params.id);
    res.redirect(`/item/${req.params.id}`);
  } catch (e) { next(e); }
});

// Delete whole item (admin or owner)
app.post('/item/:id/delete', requireAdmin, async (req, res, next) => {
  try {
    const id = req.params.id;
    const imgs = await db.all('SELECT image_path FROM images WHERE item_id=?', id);
    const one = await db.get('SELECT image_path FROM items WHERE id=?', id);
    await db.run('DELETE FROM bids WHERE item_id=?', id);
    await db.run('DELETE FROM images WHERE item_id=?', id);
    await db.run('DELETE FROM items WHERE id=?', id);
    // remove files (best-effort)
    const all = [...imgs.map(i => i.image_path), one?.image_path].filter(Boolean);
    all.forEach(p => {
      const abs = path.join(__dirname, p.replace(/^\//, ''));
      if (abs.startsWith(UPLOAD_DIR)) fs.rm(abs, { force: true }, () => {});
    });
    res.redirect('/');
  } catch (e) { next(e); }
});

// Remove single image (admin or owner)
app.post('/item/:id/image/:imgId/delete', requireAdmin, async (req, res, next) => {
  try {
    const { id, imgId } = req.params;
    const row = await db.get('SELECT image_path FROM images WHERE id=? AND item_id=?', imgId, id);
    if (!row) return res.redirect(`/item/${id}`);
    await db.run('DELETE FROM images WHERE id=?', imgId);
    // if main image equals this image -> set main to another
    const it = await db.get('SELECT image_path FROM items WHERE id=?', id);
    if (it?.image_path === row.image_path) {
      const nextImg = await db.get('SELECT image_path FROM images WHERE item_id=? ORDER BY sort_order, id LIMIT 1', id);
      if (nextImg) await db.run('UPDATE items SET image_path=? WHERE id=?', nextImg.image_path, id);
    }
    const abs = path.join(__dirname, row.image_path.replace(/^\//, ''));
    if (abs.startsWith(UPLOAD_DIR)) fs.rm(abs, { force: true }, () => {});
    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// Upload form (admin)
app.get('/admin/upload', requireAdmin, (req, res) => {
  res.render('upload');
});

// Handle upload (admin)
app.post('/admin/upload', requireAdmin, upload.array('images', 12), async (req, res, next) => {
  try {
    const { title, description, start_price, min_increment, end_time } = req.body;
    if (!req.files?.length) throw new Error('Chưa chọn ảnh');
    const id = nanoid(10);
    const firstPath = '/uploads/' + path.basename(req.files[0].path);

    await db.run(
      `INSERT INTO items(id, title, description, image_path, start_price, min_increment, end_time, status, owner_id)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      id,
      (title || '').trim().slice(0, 200),
      (description || '').trim(),
      firstPath,
      parseFloat(start_price || '0') || 0,
      parseFloat(min_increment || '1') || 1,
      end_time ? new Date(end_time).toISOString() : null,
      'active',
      (req.session.user && req.session.user.id) || null
    );

    // save gallery
    let order = 0;
    for (const f of req.files) {
      const p = '/uploads/' + path.basename(f.path);
      await db.run(
        'INSERT INTO images(item_id, image_path, sort_order) VALUES(?,?,?)',
        id, p, order++
      );
    }

    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// Users (admin)
app.get('/users', requireAdmin, async (req, res, next) => {
  try {
    const users = await db.all('SELECT id, email, display_name, verified, role, created_at FROM users ORDER BY created_at DESC LIMIT 200');
    res.render('users', { users });
  } catch (e) { next(e); }
});

// Auth (simple)
app.get('/login', (req, res) => res.render('auth-login'));
app.post('/login', express.urlencoded({ extended: true }), async (req, res) => {
  const { email, password } = req.body;
  const u = await db.get('SELECT * FROM users WHERE email=?', email.trim().toLowerCase());
  if (!u) return res.status(401).send('Sai thông tin đăng nhập');
  const ok = await bcrypt.compare(password || '', u.password_hash);
  if (!ok) return res.status(401).send('Sai thông tin đăng nhập');
  req.session.user = { id: u.id, email: u.email, display_name: u.display_name, role: u.role, verified: !!u.verified };
  res.redirect('/');
});
app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// Static pages
app.get('/about', (req, res) => res.render('about'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/privacy', (req, res) => res.render('terms')); // dùng chung template nếu chưa có

// 404
app.use((req, res) => res.status(404).render('404'));

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);
  res.status(500).send(err.message || 'Internal Server Error');
});

// ---------- BOOT ----------
const port = process.env.PORT || 3000;
await initDb();
app.listen(port, () => {
  console.log(`Auction Gallery PRO listening on http://localhost:${port}`);
});
