// server.js — Supabase ESM version (UPDATED: RBAC + verify + safe views)

import 'dotenv/config';
import dns from 'dns';
if (dns.setDefaultResultOrder) dns.setDefaultResultOrder('ipv4first');

import path from 'path';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import multer from 'multer';
import { nanoid } from 'nanoid';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';
import pkg from 'pg';
import bcrypt from 'bcryptjs';

const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== ENV checks =====
const REQUIRED = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'DATABASE_URL', 'SESSION_SECRET'];
for (const k of REQUIRED) if (!process.env[k]) console.error(`[ENV MISSING] ${k} is required`);

// ===== Supabase (Storage/API) =====
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// ===== Postgres (DB) =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

// ===== Express =====
const app = express();
if (process.env.RENDER) app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

const SITE_NAME = process.env.SITE_NAME || 'Auction Gallery PRO';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@example.com';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

app.use((req, res, next) => {
  res.locals.SITE_NAME = SITE_NAME;   // <- để head.ejs dùng được
  res.locals.SUPPORT_EMAIL = SUPPORT_EMAIL;
  res.locals.currentUser = req.session?.user || null;
  res.locals.getImageUrl = (p) => supabase.storage.from('images').getPublicUrl(p).data.publicUrl;
  next();
});

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '7d', etag: true }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 300 }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', secure: !!process.env.RENDER, maxAge: 1000 * 60 * 60 * 24 * 7 },
}));

// ===== Multer (memory) =====
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// ===== Helpers =====
function computeEnded(row) {
  const endedByStatus = row.status && row.status !== 'active';
  const endedByTime = row.end_time ? Date.now() > new Date(row.end_time).getTime() : false;
  return endedByStatus || endedByTime;
}

async function enrichItem(row) {
  const agg = await pool.query('SELECT COUNT(*)::int AS bidcount, MAX(amount) AS topbid FROM bids WHERE item_id=$1', [row.id]);
  return {
    ...row,
    start_price: row.start_price == null ? 0 : Number(row.start_price),
    min_increment: row.min_increment == null ? 0 : Number(row.min_increment),
    bidcount: agg.rows[0]?.bidcount || 0,
    topbid: agg.rows[0]?.topbid == null ? null : Number(agg.rows[0].topbid),
    ended: computeEnded(row),
  };
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.role === 'admin') return next();
  const key = req.get('x-admin-key') || req.query.admin_key || req.body?.admin_key;
  if (key && key === ADMIN_KEY) return next();
  if (req.accepts('html')) return res.status(403).render('403');
  return res.status(403).send('Forbidden');
}

async function ensureVerifiedUser(req, res, next) {
  try {
    if (!req.session?.user) return res.redirect('/login');
    if (req.session.user.role === 'admin') return next();
    const { rows } = await pool.query('SELECT verified FROM users WHERE id=$1', [req.session.user.id]);
    if (!rows[0]?.verified) return res.status(403).render('need-verify');
    next();
  } catch (e) { next(e); }
}

// ===== Routes =====
app.get('/', async (req, res, next) => {
  try {
    const PAGE_SIZE = 8;
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const q = (req.query.q || '').trim();

    let whereSQL = '';
    const params = [];
    if (q) { whereSQL = `WHERE title ILIKE $1 OR description ILIKE $1`; params.push(`%${q}%`); }

    const totalRow = await pool.query(`SELECT COUNT(*)::int AS cnt FROM items ${whereSQL}`, params);
    const total = totalRow.rows[0]?.cnt || 0;
    const totalPages = Math.max(1, Math.ceil(total / (PAGE_SIZE || 1)));
    const pageSafe = Math.min(page, totalPages);
    const offset = (pageSafe - 1) * PAGE_SIZE;

    const items = await pool.query(
      `SELECT * FROM items ${whereSQL} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, PAGE_SIZE, offset]
    );

    const full = await Promise.all(items.rows.map(enrichItem));
    const pager = { page: pageSafe, total, totalPages, hasPrev: pageSafe > 1, hasNext: pageSafe < totalPages, prev: pageSafe - 1, next: pageSafe + 1, q };
    res.render('index', { items: full, pager, q });
  } catch (e) { next(e); }
});

app.get('/item/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const itemRes = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    if (!itemRes.rows.length) return res.status(404).render('404');

    const images = await pool.query('SELECT * FROM images WHERE item_id=$1 ORDER BY sort_order, id', [id]);
    const gallery = images.rows.length ? images.rows.map((i) => i.image_path) : [itemRes.rows[0].image_path];
    const bids = await pool.query('SELECT bidder, amount, created_at FROM bids WHERE item_id=$1 ORDER BY amount DESC', [id]);

    const full = await enrichItem(itemRes.rows[0]);
    res.render('item', { item: full, gallery, imagesFull: images.rows, bids: bids.rows });
  } catch (e) { next(e); }
});

// ===== Bids =====
app.post('/item/:id/bid', ensureVerifiedUser, async (req, res, next) => {
  try {
    const id = req.params.id;
    const bidder = (req.session?.user?.email || req.body.bidder || '').trim().slice(0, 120) || 'Ẩn danh';
    const amount = Number(req.body.amount);

    const itemRes = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    if (!itemRes.rows.length) return res.status(404).send('Item not found');
    const item = await enrichItem(itemRes.rows[0]);
    if (item.ended || item.status !== 'active') return res.status(400).send('Auction ended');

    const agg = await pool.query('SELECT COALESCE(MAX(amount),0) as top FROM bids WHERE item_id=$1', [id]);
    const currentTop = Number(agg.rows[0]?.top || 0);
    const minBase = Math.max(currentTop, Number(item.start_price));
    const minReq = minBase + (Number(item.min_increment) || 1);
    if (!Number.isFinite(amount) || amount < minReq) throw new Error(`Bid must be >= ${minReq}`);

    await pool.query('INSERT INTO bids(item_id,bidder,amount) VALUES($1,$2,$3)', [id, bidder, amount]);
    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// ===== Admin: Users (RBAC) =====
app.get('/admin', requireAdmin, (req, res) => res.render('admin-dashboard'));

app.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const { rows: users } = await pool.query('SELECT id, email, display_name, role, verified, created_at FROM users ORDER BY created_at DESC');
    res.render('admin-users', { users });
  } catch (e) { next(e); }
});

app.post('/admin/users/:id/update', requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const role = (req.body.role || 'user').trim();
    const verified = req.body.verified === 'true';
    if (!['user', 'admin'].includes(role)) return res.status(400).send('role không hợp lệ');
    await pool.query('UPDATE users SET role=$1, verified=$2 WHERE id=$3', [role, verified, id]);
    if (req.session?.user?.id === id) req.session.user.role = role;
    res.redirect('/admin/users');
  } catch (e) { next(e); }
});

// ===== Admin: Upload =====
app.get('/admin/upload', requireAdmin, (req, res) => res.render('upload', { adminKey: req.query.admin_key || '' }));

// đặt upload TRƯỚC requireAdmin để đọc admin_key trong multipart nếu cần
app.post('/admin/upload', upload.array('images', 12), requireAdmin, async (req, res, next) => {
  try {
    const { title, description, start_price, min_increment, end_time } = req.body;
    if (!req.files?.length) throw new Error('Chưa chọn ảnh');

    const id = nanoid(10);
    await pool.query(
      `INSERT INTO items(id, title, description, image_path, start_price, min_increment, end_time, status, owner_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
      [
        id,
        String(title || '').trim().slice(0, 200),
        String(description || '').trim(),
        '/uploads/placeholder.png',
        Number(start_price) || 0,
        Number(min_increment) || 1,
        end_time ? new Date(end_time).toISOString() : null,
        req.session.user?.id || null,
      ]
    );

    let order = 0;
    let firstPath = null;
    for (const f of req.files) {
      const ext = (f.mimetype?.split('/')[1] || 'bin').toLowerCase();
      const objectName = `items/${id}/${Date.now()}_${nanoid(6)}.${ext}`;

      const { error } = await supabase.storage.from('images').upload(objectName, f.buffer, {
        contentType: f.mimetype || 'application/octet-stream',
      });
      if (error) throw error;
      if (!firstPath) firstPath = objectName;
      await pool.query('INSERT INTO images(item_id, image_path, sort_order) VALUES($1,$2,$3)', [id, objectName, order++]);
    }

    if (firstPath) await pool.query('UPDATE items SET image_path=$1 WHERE id=$2', [firstPath, id]);
    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// ===== Auth =====
app.get('/login', (req, res) => res.render('auth-login', { email: '', error: null }));

app.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT id, email, password_hash, display_name, role FROM users WHERE email=$1', [email]);
    const u = q.rows[0];
    if (!u) return res.status(401).render('auth-login', { error: 'Tài khoản không tồn tại', email });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).render('auth-login', { error: 'Sai mật khẩu', email });
    req.session.user = { id: u.id, email: u.email, name: u.display_name, role: u.role };
    res.redirect('/');
  } catch (e) { next(e); }
});

app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// ===== Health =====
app.get('/_health', async (req, res) => {
  try {
    const r = await pool.query('select now() as now');
    res.json({ ok: true, db_time: r.rows[0].now, supabase_url: !!process.env.SUPABASE_URL });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});
app.get('/_sb', async (req, res) => {
  const { data, error } = await supabase.storage.from('images').list('', { limit: 1 });
  res.json({ ok: !error, error: error?.message, data });
});

// ===== 404 & error =====
app.use((req, res) => {
  try { return res.status(404).render('404'); }
  catch { return res.status(404).send('404 - Not found'); }
});

app.use((err, req, res, next) => {
  console.error('❌', err);
  if (req.accepts('html')) {
    try { return res.status(500).render('500', { error: err }); }
    catch { return res.status(500).send('500 - Internal Server Error'); }
  }
  res.status(500).json({ error: String(err) });
});

// ===== Boot =====
const port = process.env.PORT || 3000;
app.listen(port, () => { console.log(`✅ App on http://localhost:${port}`); });