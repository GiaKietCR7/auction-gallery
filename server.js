// server.js — bản đầy đủ (Express + EJS + RBAC + verify + Supabase Storage)
// YÊU CẦU ENV:
// PORT=3000
// DATABASE_URL=postgresql://... (Supabase → Project Settings → Database → Connection string)
// SESSION_SECRET=your-strong-secret
// SUPABASE_URL=https://xxxxx.supabase.co
// SUPABASE_SERVICE_ROLE_KEY=eyJ... (Project Settings → API → Service role)
// ADMIN_KEY=optional-secret (để mở /admin/upload tạm thời nếu cần)
// NODE_ENV=production (khi deploy, để bật cookie secure)

require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

// ====== KẾT NỐI DATABASE (PG) ======
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ====== SUPABASE (server) ======
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ====== APP ======
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Trust proxy để cookie Secure hoạt động sau reverse proxy (Render/Vercel/Fly/Heroku...)
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 ngày
  }
}));

// ====== HELPERS: AUTH / RBAC / VERIFY ======
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user || req.session.user.role !== 'admin') {
    if (req.accepts('html')) return res.status(403).render('403', { me: req.session.user });
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

async function ensureVerifiedUser(req, res, next) {
  try {
    if (!req.session?.user) return res.redirect('/login');
    if (req.session.user.role === 'admin') return next(); // admin bỏ qua verify

    const { rows } = await pool.query('select verified from users where id=$1', [req.session.user.id]);
    const u = rows[0];
    if (!u?.verified) {
      if (req.accepts('html')) return res.status(403).render('need-verify', { me: req.session.user });
      return res.status(403).json({ error: 'Tài khoản chưa được xác minh' });
    }
    next();
  } catch (e) { next(e); }
}

// ====== VIEW LOCALS ======
app.use((req, res, next) => {
  res.locals.me = req.session?.user || null;
  next();
});

// ====== ROUTES: AUTH ======
app.get('/login', (req, res) => {
  if (req.session?.user) return res.redirect('/');
  res.render('auth-login', { error: null, email: '' });
});

app.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const q = await pool.query(
      'select id, email, password_hash, display_name, role, verified from users where email=$1',
      [email]
    );
    const u = q.rows[0];

    if (!u) {
      console.warn('[LOGIN] user not found:', email);
      return res.status(401).render('auth-login', { error: 'Tài khoản không tồn tại', email });
    }
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) {
      console.warn('[LOGIN] bad password for:', email);
      return res.status(401).render('auth-login', { error: 'Sai mật khẩu', email });
    }

    req.session.user = {
      id: u.id,
      email: u.email,
      name: u.display_name,
      role: u.role,
    };
    res.redirect('/');
  } catch (e) { next(e); }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ====== ROUTES: ADMIN ======
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin-dashboard', { me: req.session.user });
});

app.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const { rows: users } = await pool.query(
      `select id, email, display_name, role, verified, created_at
       from users
       order by created_at desc`
    );
    res.render('admin-users', { users, me: req.session.user });
  } catch (e) { next(e); }
});

app.post('/admin/users/:id/update', requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const role = (req.body.role || 'user').trim(); // 'user' | 'admin'
    const verified = req.body.verified === 'true';

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'role không hợp lệ' });
    }

    await pool.query('update users set role=$1, verified=$2 where id=$3', [role, verified, id]);

    if (req.session.user.id === id) {
      req.session.user.role = role;
    }
    res.redirect('/admin/users');
  } catch (e) { next(e); }
});

// ====== ROUTES: ITEMS (ví dụ) ======
// NOTE: Bạn có thể thay đổi logic theo app hiện tại của bạn

// Trang chủ: liệt kê items phân trang
app.get('/', async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const limit = 9; // đổi 8 nếu cần
    const offset = (page - 1) * limit;

    const { rows: items } = await pool.query(
      `select id, title, description, image_path, start_price, min_increment, end_time, status
       from items
       order by created_at desc
       limit $1 offset $2`,
      [limit, offset]
    );
    const { rows: countRows } = await pool.query('select count(*)::int as total from items');
    const total = countRows[0].total;
    const totalPages = Math.max(Math.ceil(total / limit), 1);

    res.render('index', { items, page, totalPages });
  } catch (e) { next(e); }
});

// Tạo item (admin luôn được; user thường cần verified)
app.get('/items/new', requireAdmin, (req, res) => {
  res.render('item-new');
});

app.post('/items', requireAuth, ensureVerifiedUser, async (req, res, next) => {
  try {
    const ownerId = req.session.user.id;
    const { id, title, description, image_path, start_price, min_increment, end_time } = req.body;

    await pool.query(
      `insert into items (id, title, description, image_path, start_price, min_increment, end_time, owner_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, title, description || null, image_path, start_price, min_increment || 1, end_time || null, ownerId]
    );

    res.redirect('/');
  } catch (e) { next(e); }
});

// Xem item
app.get('/items/:id', async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from items where id=$1', [req.params.id]);
    const item = rows[0];
    if (!item) return res.status(404).render('404');

    const { rows: bids } = await pool.query(
      'select id, bidder, amount, created_at from bids where item_id=$1 order by created_at desc',
      [req.params.id]
    );

    // Gallery: nếu bạn lưu nhiều path, bạn có thể split theo "," hoặc truy vấn bảng khác
    const gallery = item.image_path ? [item.image_path] : [];

    res.render('item', { item, bids, gallery });
  } catch (e) { next(e); }
});

// Sửa & xoá item (admin)
app.get('/items/:id/edit', requireAdmin, async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from items where id=$1', [req.params.id]);
    const item = rows[0];
    if (!item) return res.status(404).render('404');
    res.render('item-edit', { item });
  } catch (e) { next(e); }
});

app.post('/items/:id/delete', requireAdmin, async (req, res, next) => {
  try {
    await pool.query('delete from items where id=$1', [req.params.id]);
    res.redirect('/');
  } catch (e) { next(e); }
});

// ====== ROUTES: BIDS (đặt giá) ======
app.post('/bids', requireAuth, ensureVerifiedUser, async (req, res, next) => {
  try {
    const { item_id, amount } = req.body;
    await pool.query(
      `insert into bids (item_id, bidder, amount) values ($1, $2, $3)`,
      [item_id, req.session.user.email, amount]
    );
    res.redirect('/items/' + item_id);
  } catch (e) { next(e); }
});

// ====== UPLOAD ẢNH LÊN SUPABASE STORAGE (SERVER) ======
// Bucket: images (public). Bạn đã tạo policy service_role full, client select.
const upload = multer({ storage: multer.memoryStorage() });

// Trang upload (admin) — có thể mở bằng admin_key nếu cần seed nhanh
app.get('/admin/upload', async (req, res, next) => {
  const key = req.query.admin_key || req.headers['x-admin-key'];
  if (!req.session?.user || req.session.user.role !== 'admin') {
    if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) {
      return res.status(403).render('403', { me: req.session.user });
    }
  }
  res.render('admin-upload');
});

app.post('/admin/upload', upload.single('file'), async (req, res, next) => {
  try {
    const key = req.query.admin_key || req.headers['x-admin-key'];
    if (!req.session?.user || req.session.user.role !== 'admin') {
      if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }

    if (!req.file) return res.status(400).json({ error: 'Thiếu file' });

    const fileBuffer = req.file.buffer;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const filename = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
    const storagePath = `uploads/${filename}`; // bạn có thể đổi sang `${userId}/...`

    const { error } = await supabase.storage
      .from('images')
      .upload(storagePath, fileBuffer, {
        contentType: req.file.mimetype,
        upsert: false
      });
    if (error) throw error;

    const { data: pub } = supabase.storage.from('images').getPublicUrl(storagePath);
    res.json({ ok: true, path: storagePath, publicUrl: pub.publicUrl });
  } catch (e) { next(e); }
});

// ====== HEALTHCHECK / DEBUG ======
app.get('/_health', async (req, res) => {
  try {
    const { rows } = await pool.query('select now() as now');
    res.json({ ok: true, db_time: rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get('/_sb', async (req, res) => {
  try {
    // Liệt kê 1 object trong bucket images (nếu có) để test quyền
    const { data, error } = await supabase.storage.from('images').list('', { limit: 1 });
    if (error) throw error;
    res.json({ ok: true, sample: data });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ====== 404 & ERROR HANDLERS ======
app.use((req, res) => {
  res.status(404).render('404');
});

app.use((err, req, res, next) => {
  console.error(err);
  if (req.accepts('html')) return res.status(500).render('500', { error: err });
  res.status(500).json({ error: String(err) });
});

// ====== START ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Server listening on http://localhost:' + PORT);
});
