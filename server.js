// server.js — Supabase version (FULL)
// ----------------------------------------------------
// npm i @supabase/supabase-js pg multer helmet express-rate-limit nanoid bcryptjs
// ----------------------------------------------------

import 'dotenv/config';
import dns from 'dns';
if (dns.setDefaultResultOrder) dns.setDefaultResultOrder('ipv4first'); // ưu tiên IPv4

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

// ====== ENV sanity check ======
const REQUIRED = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'DATABASE_URL', 'SESSION_SECRET'];
for (const k of REQUIRED) {
  if (!process.env[k]) {
    console.error(`[ENV MISSING] ${k} is required`);
  }
}

// ====== Supabase client (Storage, etc) ======
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ====== Postgres Pool (Supabase DB) ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  // timeouts hợp lý hơn trên Render
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

// ====== Express app ======
const app = express();
if (process.env.RENDER) app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

const SITE_NAME = process.env.SITE_NAME || 'Auction Gallery PRO';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@example.com';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

app.use((req, res, next) => {
  res.locals.SITE_NAME = SITE_NAME;
  res.locals.SUPPORT_EMAIL = SUPPORT_EMAIL;
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '7d', etag: true }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 1000, max: 300 }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: !!process.env.RENDER,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);
app.use((req, res, next) => {
  // luôn đặt biến cho EJS để không bị undefined
  res.locals.currentUser = req.session?.user || null;
  res.locals.getImageUrl = getImageUrl; // nếu head/partials cần dùng
  next();
});
// ====== Multer (memory) ======
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB/ảnh
});

// ====== Helpers ======
function computeEnded(row) {
  const endedByStatus = row.status && row.status !== 'active';
  const endedByTime = row.end_time ? Date.now() > new Date(row.end_time).getTime() : false;
  return endedByStatus || endedByTime;
}

async function enrichItem(row) {
  const agg = await pool.query(
    `SELECT COUNT(*)::int as bidcount, MAX(amount) as topbid FROM bids WHERE item_id=$1`,
    [row.id]
  );
  return {
    ...row,
    bidcount: agg.rows[0]?.bidcount || 0,
    topbid: agg.rows[0]?.topbid || null,
    ended: computeEnded(row),
  };
}

function getImageUrl(p) {
  return supabase.storage.from('images').getPublicUrl(p).data.publicUrl;
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.role === 'admin') return next();
  const key =
    req.get('x-admin-key') ||
    req.query.admin_key ||
    req.body?.admin_key;           // ← nhận key từ body khi POST form
  if (key && key === ADMIN_KEY) return next();
  return res.status(403).send('Forbidden');
}

// ====== Routes ======

// Home + pagination + search
app.get('/', async (req, res, next) => {
  try {
    const PAGE_SIZE = 8;
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const q = (req.query.q || '').trim();

    let whereSQL = '';
    const params = [];
    if (q) {
      whereSQL = `WHERE title ILIKE $1 OR description ILIKE $1`;
      params.push(`%${q}%`);
    }

    const totalRow = await pool.query(`SELECT COUNT(*)::int AS cnt FROM items ${whereSQL}`, params);
    const total = totalRow.rows[0]?.cnt || 0;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const pageSafe = Math.min(page, totalPages);
    const offset = (pageSafe - 1) * PAGE_SIZE;

    const items = await pool.query(
      `SELECT * FROM items ${whereSQL} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, PAGE_SIZE, offset]
    );

    const full = await Promise.all(items.rows.map(enrichItem));
    const pager = {
      page: pageSafe,
      total,
      totalPages,
      hasPrev: pageSafe > 1,
      hasNext: pageSafe < totalPages,
      prev: pageSafe - 1,
      next: pageSafe + 1,
      q,
    };
    res.render('index', { items: full, pager, q, getImageUrl });
  } catch (e) {
    next(e);
  }
});

// Item detail
app.get('/item/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const itemRes = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    if (!itemRes.rows.length) return res.status(404).render('404');

    const images = await pool.query('SELECT * FROM images WHERE item_id=$1 ORDER BY sort_order, id', [id]);
    const gallery = images.rows.length ? images.rows.map((i) => i.image_path) : [itemRes.rows[0].image_path];
    const bids = await pool.query('SELECT bidder, amount FROM bids WHERE item_id=$1 ORDER BY amount DESC', [id]);
    const full = await enrichItem(itemRes.rows[0]);

    res.render('item', { item: full, gallery, imagesFull: images.rows, bids: bids.rows, getImageUrl });
  } catch (e) {
    next(e);
  }
});

// Place bid
app.post('/item/:id/bid', async (req, res, next) => {
  try {
    const id = req.params.id;
    const bidder = (req.body.bidder || '').trim().slice(0, 60) || 'Ẩn danh';
    const amount = parseFloat(req.body.amount);

    const itemRes = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    const item = itemRes.rows[0];
    if (!item) return res.status(404).send('Item not found');
    if (computeEnded(item) || item.status !== 'active') return res.status(400).send('Auction ended');

    const agg = await pool.query('SELECT COALESCE(MAX(amount),0) as top FROM bids WHERE item_id=$1', [id]);
    const currentTop = parseFloat(agg.rows[0]?.top || 0);
    const minBase = Math.max(currentTop, parseFloat(item.start_price));
    const minReq = minBase + (parseFloat(item.min_increment) || 1);
    if (!Number.isFinite(amount) || amount < minReq) throw new Error(`Bid must be >= ${minReq}`);

    await pool.query('INSERT INTO bids(item_id,bidder,amount) VALUES($1,$2,$3)', [id, bidder, amount]);
    res.redirect(`/item/${id}`);
  } catch (e) {
    next(e);
  }
});

// Upload form
app.post('/admin/upload', upload.array('images', 12), requireAdmin, async (req, res, next) => {

// Handle upload — INSERT item trước, rồi upload ảnh + insert images, cuối cùng update image_path
app.post('/admin/upload', requireAdmin, upload.array('images', 12), async (req, res, next) => {
  try {
    const { title, description, start_price, min_increment, end_time } = req.body;
    if (!req.files?.length) throw new Error('Chưa chọn ảnh');

    const id = nanoid(10);

    // 1) Tạo item trước để đảm bảo FK hợp lệ
    await pool.query(
      `INSERT INTO items(id, title, description, image_path, start_price, min_increment, end_time, status, owner_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
      [
        id,
        String(title || '').trim().slice(0, 200),
        String(description || '').trim(),
        '/uploads/placeholder.png',
        parseFloat(start_price) || 0,
        parseFloat(min_increment) || 1,
        end_time ? new Date(end_time).toISOString() : null,
        req.session.user?.id || null,
      ]
    );

    // 2) Upload ảnh và insert bảng images
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

      await pool.query('INSERT INTO images(item_id, image_path, sort_order) VALUES($1,$2,$3)', [
        id,
        objectName,
        order++,
      ]);
    }

    // 3) Cập nhật ảnh đại diện
    if (firstPath) {
      await pool.query('UPDATE items SET image_path=$1 WHERE id=$2', [firstPath, id]);
    }

    res.redirect(`/item/${id}`);
  } catch (e) {
    next(e);
  }
});

// ====== Auth (đủ dùng cho admin) ======
app.get('/login', (req, res) => res.render('auth-login'));
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const q = await pool.query('SELECT id, email, password_hash, display_name, role FROM users WHERE email=$1', [
      String(email || '').trim().toLowerCase(),
    ]);
    const u = q.rows[0];
    if (!u) return res.status(401).render('auth-login', { error: 'Tài khoản không tồn tại' });

    const ok = await bcrypt.compare(String(password || ''), u.password_hash);
    if (!ok) return res.status(401).render('auth-login', { error: 'Sai mật khẩu' });

    req.session.user = { id: u.id, email: u.email, name: u.display_name, role: u.role };
    res.redirect('/');
  } catch (e) {
    next(e);
  }
});
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ====== Static pages ======
app.get('/about', (req, res) => res.render('about'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/contact', (req, res) => res.render('contact'));

// ====== Health & Supabase check ======
app.get('/_health', async (req, res) => {
  try {
    const r = await pool.query('select now() as now');
    res.json({ ok: true, db_time: r.rows[0].now, supabase_url: !!process.env.SUPABASE_URL });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});
app.get('/_sb', async (req, res) => {
  const { data, error } = await supabase.storage.from('images').list({ limit: 1 });
  res.json({ ok: !error, error: error?.message, data });
});

// ====== 404 & error handler ======
app.use((req, res) => res.status(404).render('404'));
app.use((err, req, res, next) => {
  console.error('❌', err);
  res.status(500).send(err.message || 'Internal Error');
});

// ====== Boot ======
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`✅ App on http://localhost:${port}`);
});
