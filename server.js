import express from 'express';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { customAlphabet } from 'nanoid';
import mime from 'mime';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import session from 'express-session';
import SQLiteStoreImport from 'connect-sqlite3';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// === DB PATH (hỗ trợ free tier Render) ===
const DATA_DIR = process.env.DB_DIR || path.join(__dirname, 'data');
// Ưu tiên biến môi trường DB_FILE; nếu không có thì dùng ./data/app.db (chạy local)
const DB_FILE  = process.env.DB_FILE || path.join(DATA_DIR, 'app.db');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

// Security
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "img-src": ["'self'", "data:", "blob:", "https:"],
      "style-src": ["'self'", "https:", "'unsafe-inline'"],
      "script-src": ["'self'", "https:", "'unsafe-inline'"]
    }
  }
}));
const limiter = rateLimit({ windowMs: 60 * 1000, limit: 180 });
app.use(limiter);

// Views & body
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure dirs
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
// Nếu DB_FILE không nằm ở /tmp thì tạo thư mục chứa nó
if (!DB_FILE.startsWith('/tmp')) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
}

// Sessions (PHẢI trước các route)
const SQLiteStore = SQLiteStoreImport(session);
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'data') }),
  secret: process.env.SESSION_SECRET || 'secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 } // 7 ngày
}));
app.use((req,res,next)=>{
  res.locals.currentUser = req.session.user || null;
  next();
});

// Upload (multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => {
    const nanoid = customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 10);
    const id = nanoid();
    const ext = mime.getExtension(file.mimetype) || 'bin';
    cb(null, `${id}.${ext}`);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png','image/jpeg','image/webp','image/gif'];
    if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Only images allowed'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});
const uploadMany = upload.array('images', 12); // upload nhiều ảnh

// DB
let db;
(async () => {
  db = await open({ filename: DB_FILE, driver: sqlite3.Database });
console.log('✅ Using SQLite file at:', DB_FILE);
  await db.exec(`
    PRAGMA journal_mode = WAL;

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

  // migrate (nếu thiếu)
  const info = await db.all(`PRAGMA table_info(items)`);
  const cols = info.map(r => r.name);
  const alters = [];
  if (!cols.includes('min_increment')) alters.push(`ALTER TABLE items ADD COLUMN min_increment REAL NOT NULL DEFAULT 1;`);
  if (!cols.includes('end_time'))     alters.push(`ALTER TABLE items ADD COLUMN end_time DATETIME;`);
  if (!cols.includes('status'))       alters.push(`ALTER TABLE items ADD COLUMN status TEXT NOT NULL DEFAULT 'active';`);
  if (!cols.includes('owner_id'))     alters.push(`ALTER TABLE items ADD COLUMN owner_id INTEGER;`);
  for (const q of alters) await db.exec(q);

  // Seed admin mặc định
  const admin = await db.get("SELECT * FROM users WHERE role='admin'");
  if (!admin) {
    const hash = await bcrypt.hash('admin123', 11);
    await db.run(
      "INSERT INTO users (email, password_hash, display_name, verified, role) VALUES (?,?,?,?,?)",
      ['admin@site.local', hash, 'Administrator', 1, 'admin']
    );
    console.log("✅ Đã tạo tài khoản admin mặc định: email=admin@site.local, pass=admin123");
  }
})();

// Utils
const idGen = customAlphabet('23456789abcdefghijkmnopqrstuvwxyz', 8);
async function getItemWithStats(itemId) {
  const item = await db.get('SELECT * FROM items WHERE id = ?', itemId);
  if (!item) return null;
  const topBid = await db.get('SELECT amount FROM bids WHERE item_id = ? ORDER BY amount DESC LIMIT 1', itemId);
  const bidCount = await db.get('SELECT COUNT(*) as c FROM bids WHERE item_id = ?', itemId);
  const now = new Date();
  const ended = item.end_time ? (new Date(item.end_time) <= now) : false;
  return { ...item, topBid: topBid?.amount || null, bidCount: bidCount?.c || 0, ended };
}

function requireAuth(req,res,next){
  if (req.session?.user) return next();
  res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}
function requireAdmin(req,res,next){
  const key = req.query.key || req.headers['x-admin-key'] || req.body.key;
  if (key === ADMIN_KEY) return next();                 // cách cũ
  if (req.session?.user?.role === 'admin') return next(); // user admin
  return res.status(401).send('Unauthorized');
}

// NEW: chỉ cho phép chủ bài hoặc admin
async function requireOwnerOrAdmin(req, res, next) {
  try {
    const item = await db.get('SELECT id, owner_id FROM items WHERE id=?', [req.params.id]);
    if (!item) return res.status(404).send('Item not found');
    const u = req.session?.user;
    if (u && (u.role === 'admin' || u.id === item.owner_id)) {
      req.itemOwnerId = item.owner_id;
      return next();
    }
    return res.status(401).send('Unauthorized');
  } catch (e) {
    return res.status(400).send(e.message);
  }
}

// Routes

// Home (JOIN để có tác giả & bìa)
app.get('/', async (req, res) => {
  const { q, sort, status } = req.query;
  const params = [];
  let where = [];
  let sql = `
    SELECT i.*,
           u.display_name, u.verified,
           (
             SELECT img.image_path
             FROM images img
             WHERE img.item_id = i.id
             ORDER BY img.sort_order ASC, img.id ASC
             LIMIT 1
           ) AS cover_image,
           (SELECT MAX(amount) FROM bids b WHERE b.item_id = i.id) as topBid
    FROM items i
    LEFT JOIN users u ON i.owner_id = u.id
  `;
 if (q) {
  where.push('(i.title LIKE ? OR i.description LIKE ?)');
  params.push(`%${q}%`, `%${q}%`);
}

  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  if (sort === 'price') sql += ' ORDER BY COALESCE(topBid, start_price) DESC';
  else if (sort === 'new') sql += ' ORDER BY i.created_at DESC';
  else sql += ' ORDER BY i.rowid DESC';
  const items = await db.all(sql, params);
  res.render('index', { items, q: q || '', sort: sort || '', status: status || '' });
});

// Auth views
app.get('/signup', (req,res)=> res.render('auth-signup', { title: 'Đăng ký' }));
app.get('/login',  (req,res)=> res.render('auth-login',  { title: 'Đăng nhập', next: req.query.next || '/' }));

// Signup
app.post('/signup', async (req,res)=>{
  try{
    const { email, password, display_name } = req.body;
    if (!email || !password || !display_name) throw new Error('Thiếu thông tin');
    const hash = await bcrypt.hash(password, 11);
    await db.run('INSERT INTO users (email, password_hash, display_name) VALUES (?,?,?)',
      [email.trim().toLowerCase(), hash, display_name.trim()]);
    res.redirect('/login');
  }catch(e){ res.status(400).send(e.message); }
});

// Login
app.post('/login', async (req,res)=>{
  try{
    const { email, password, next } = req.body;
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (!user) throw new Error('Sai email hoặc mật khẩu');
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) throw new Error('Sai email hoặc mật khẩu');
    req.session.user = { id:user.id, email:user.email, display_name:user.display_name, verified:!!user.verified, role:user.role };
    res.redirect(next || '/');
  }catch(e){ res.status(400).send(e.message); }
});

// Logout
app.post('/logout', (req,res)=>{ req.session.destroy(()=> res.redirect('/')); });

// Upload (chỉ user đã login) — nhiều ảnh
app.get('/admin/upload', requireAuth, (req, res) => {
  res.render('upload', { admin: false, key: '', user: req.session.user });
});
app.post('/admin/upload', requireAuth, uploadMany, async (req,res)=>{
  try {
    const { title, description, start_price, min_increment, end_time } = req.body;
    const files = req.files || [];
    const price = Number(start_price);
    const inc = Number(min_increment || 1);
    if (!title || Number.isNaN(price) || price < 0) throw new Error('Invalid data');
    if (!files.length) throw new Error('Vui lòng chọn ít nhất 1 ảnh');

    const id = idGen();
    const cover = `/uploads/${path.basename(files[0].path)}`;
    await db.run(
      'INSERT INTO items (id, title, description, image_path, start_price, min_increment, end_time, status, owner_id) VALUES (?,?,?,?,?,?,?,?,?)',
      [id, title.trim(), (description||'').trim(), cover, price, inc, end_time || null, 'active', req.session.user.id]
    );

    let order = 0;
    for (const f of files) {
      const p = `/uploads/${path.basename(f.path)}`;
      await db.run(`INSERT INTO images (item_id, image_path, sort_order) VALUES (?,?,?)`, [id, p, order++]);
    }

    res.redirect(`/item/${id}`);
  } catch (e) { res.status(400).send(e.message); }
});

// Item detail (gallery nhiều ảnh) — trả thêm imagesFull
app.get('/item/:id', async (req,res)=>{
  const item = await getItemWithStats(req.params.id);
  if (!item) return res.status(404).render('404');
  const bids = await db.all('SELECT * FROM bids WHERE item_id=? ORDER BY amount DESC, created_at DESC', item.id);
  const owner = item.owner_id ? await db.get('SELECT id, display_name, verified FROM users WHERE id=?', item.owner_id) : null;
  const imagesFull = await db.all('SELECT id, image_path FROM images WHERE item_id=? ORDER BY sort_order ASC, id ASC', item.id);
  const gallery = imagesFull.length ? imagesFull.map(r=>r.image_path) : [item.image_path];
  res.render('item', { item, bids, owner, gallery, imagesFull });
});

// Bid
app.post('/item/:id/bid', async (req, res) => {
  try {
    const item = await getItemWithStats(req.params.id);
    if (!item) return res.status(404).send('Item not found');
    if (item.ended || item.status !== 'active') throw new Error('Auction ended or inactive');
    const { bidder, amount } = req.body;
    const bidAmount = Number(amount);
    if (!bidder || !bidder.trim()) throw new Error('Bidder name required');
    if (Number.isNaN(bidAmount) || bidAmount <= 0) throw new Error('Invalid bid amount');
    const minBase = Math.max(item.start_price, item.topBid || 0);
    const minRequired = minBase + (item.min_increment || 1) - 1e-9;
    if (bidAmount < minRequired) throw new Error(`Bid must be at least ${(minBase + item.min_increment).toFixed(2)}`);
    await db.run('INSERT INTO bids (item_id, bidder, amount) VALUES (?,?,?)', [item.id, bidder.trim(), bidAmount]);
    res.redirect(`/item/${item.id}`);
  } catch (e) { res.status(400).send(e.message); }
});

// Close auction (admin)
app.post('/item/:id/close', requireAdmin, async (req, res) => {
  await db.run('UPDATE items SET status=? WHERE id=?', ['ended', req.params.id]);
  res.redirect(`/item/${req.params.id}`);
});

// NEW: Delete toàn bộ bài (file + DB) — chủ bài hoặc admin
app.post('/item/:id/delete', requireOwnerOrAdmin, async (req, res) => {
  try {
    const imgRows = await db.all('SELECT image_path FROM images WHERE item_id=?', [req.params.id]);
    const itemRow = await db.get('SELECT image_path FROM items WHERE id=?', [req.params.id]);

    const allPaths = [...imgRows.map(r => r.image_path)];
    if (itemRow?.image_path) allPaths.push(itemRow.image_path);

    for (const p of allPaths) {
      try {
        const abs = path.join(__dirname, p.replace(/^\//, ''));
        await fs.promises.unlink(abs);
      } catch {}
    }

    await db.run('DELETE FROM bids   WHERE item_id=?', [req.params.id]);
    await db.run('DELETE FROM images WHERE item_id=?', [req.params.id]);
    await db.run('DELETE FROM items  WHERE id=?',      [req.params.id]);

    res.redirect('/');
  } catch (e) {
    res.status(400).send(e.message);
  }
});

// NEW: Gỡ 1 ảnh trong bài — chủ bài hoặc admin
app.post('/item/:id/image/:imgId/delete', requireOwnerOrAdmin, async (req, res) => {
  try {
    const img = await db.get(
      'SELECT id, image_path FROM images WHERE id=? AND item_id=?',
      [req.params.imgId, req.params.id]
    );
    if (!img) return res.status(404).send('Image not found');

    try {
      const abs = path.join(__dirname, img.image_path.replace(/^\//, ''));
      await fs.promises.unlink(abs);
    } catch {}

    await db.run('DELETE FROM images WHERE id=?', [req.params.imgId]);

    // nếu ảnh trùng cover hiện tại => cập nhật cover mới
    const item = await db.get('SELECT image_path FROM items WHERE id=?', [req.params.id]);
    if (item?.image_path === img.image_path) {
      const nextCover = await db.get(
        'SELECT image_path FROM images WHERE item_id=? ORDER BY sort_order ASC, id ASC LIMIT 1',
        [req.params.id]
      );
      await db.run('UPDATE items SET image_path=? WHERE id=?', [nextCover ? nextCover.image_path : '', req.params.id]);
    }

    res.redirect(`/item/${req.params.id}`);
  } catch (e) {
    res.status(400).send(e.message);
  }
});

// Info pages
app.get('/contact', (req,res)=> res.render('contact'));
app.get('/about',   (req,res)=> res.render('about'));
app.get('/terms',   (req,res)=> res.render('terms'));
app.get('/privacy', (req,res)=> res.render('privacy'));

// Contact submit
app.post('/contact', async (req,res)=>{
  try{
    const { name, email, subject, message, website } = req.body;
    if (website) return res.redirect('/contact'); // honeypot
    if (!name || !email || !message) throw new Error('Thiếu thông tin');
    await db.run('INSERT INTO contacts (name,email,subject,message) VALUES (?,?,?,?)',
      [name.trim(), email.trim(), (subject||'').trim(), message.trim()]);
    res.render('contact', { title: 'Liên hệ', success: true });
  }catch(e){ res.status(400).send(e.message); }
});

// User management (admin)
app.get('/users', requireAdmin, async (req,res)=>{
  const users = await db.all('SELECT id, email, display_name, verified, role FROM users');
  res.render('users', { users });
});
app.post('/admin/verify/:id', requireAdmin, async (req,res)=>{
  await db.run('UPDATE users SET verified = 1 WHERE id=?', [req.params.id]);
  res.redirect('/users');
});
app.post('/admin/unverify/:id', requireAdmin, async (req,res)=>{
  await db.run('UPDATE users SET verified = 0 WHERE id=?', [req.params.id]);
  res.redirect('/users');
});

// 404
app.use((req, res) => res.status(404).render('404'));

// Start
app.listen(PORT, () => {
  console.log(`Auction Gallery PRO listening on http://localhost:${PORT}`);
});
