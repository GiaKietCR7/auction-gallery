// server.js – bản Supabase
import 'dotenv/config';
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

const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Supabase ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Supabase Postgres connection string
  ssl: { rejectUnauthorized: false }
});

// ---------- App ----------
const app = express();
if (process.env.RENDER) app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

const SITE_NAME = process.env.SITE_NAME || 'Auction Gallery PRO';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@example.com';

app.use((req, res, next) => {
  res.locals.SITE_NAME = SITE_NAME;
  res.locals.SUPPORT_EMAIL = SUPPORT_EMAIL;
  next();
});

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use('/public', express.static(path.join(__dirname, 'public'), { maxAge: '7d', etag: true }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.json());

app.use(rateLimit({ windowMs: 60 * 1000, max: 300 }));

// Sessions (memory store cho demo, có thể đổi sang Redis nếu cần)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!process.env.RENDER,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  }
}));

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// ---------- Multer (upload vào memory) ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// ---------- Utils ----------
function computeEnded(row) {
  const endedByStatus = row.status && row.status !== 'active';
  const endedByTime = row.end_time ? (Date.now() > new Date(row.end_time).getTime()) : false;
  return endedByStatus || endedByTime;
}
async function enrichItem(row) {
  const agg = await pool.query(
    `SELECT COUNT(*) as bidCount, MAX(amount) as topBid
     FROM bids WHERE item_id = $1`, [row.id]);
  return {
    ...row,
    bidcount: parseInt(agg.rows[0]?.bidcount || 0),
    topbid: agg.rows[0]?.topbid || null,
    ended: computeEnded(row),
  };
}
function getImageUrl(path) {
  return supabase.storage.from('images').getPublicUrl(path).data.publicUrl;
}

// ---------- Routes ----------

// Home (gallery + pagination)
app.get('/', async (req, res, next) => {
  try {
    const PAGE_SIZE = 8;
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const q = (req.query.q || '').trim();

    let whereSQL = '';
    let params = [];
    if (q) {
      whereSQL = `WHERE title ILIKE $1 OR description ILIKE $1`;
      params.push(`%${q}%`);
    }

    const totalRow = await pool.query(`SELECT COUNT(*) as cnt FROM items ${whereSQL}`, params);
    const total = parseInt(totalRow.rows[0]?.cnt || 0);
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const pageSafe = Math.min(page, totalPages);
    const offset = (pageSafe - 1) * PAGE_SIZE;

    const items = await pool.query(
      `SELECT * FROM items ${whereSQL} ORDER BY created_at DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`,
      [...params, PAGE_SIZE, offset]
    );

    const full = await Promise.all(items.rows.map(enrichItem));
    const pager = { page: pageSafe, total, totalPages, hasPrev: pageSafe>1, hasNext: pageSafe<totalPages, prev: pageSafe-1, next: pageSafe+1, q };
    res.render('index', { items: full, pager, q, getImageUrl });
  } catch (e) { next(e); }
});

// Item detail
app.get('/item/:id', async (req, res, next) => {
  try {
    const id = req.params.id;
    const item = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    if (!item.rows.length) return res.status(404).render('404');

    const images = await pool.query('SELECT * FROM images WHERE item_id=$1 ORDER BY sort_order,id', [id]);
    const gallery = images.rows.length ? images.rows.map(i=>i.image_path) : [item.rows[0].image_path];
    const bids = await pool.query('SELECT bidder, amount FROM bids WHERE item_id=$1 ORDER BY amount DESC', [id]);

    const full = await enrichItem(item.rows[0]);
    res.render('item', { item: full, gallery, imagesFull: images.rows, bids: bids.rows, getImageUrl });
  } catch (e) { next(e); }
});

// Place bid
app.post('/item/:id/bid', async (req, res, next) => {
  try {
    const id = req.params.id;
    const bidder = (req.body.bidder || '').trim().slice(0,60);
    const amount = parseFloat(req.body.amount);

    const itemRes = await pool.query('SELECT * FROM items WHERE id=$1', [id]);
    const item = itemRes.rows[0];
    if (!item) return res.status(404).send('Item not found');
    if (computeEnded(item) || item.status !== 'active') return res.status(400).send('Auction ended');

    const agg = await pool.query('SELECT COALESCE(MAX(amount),0) as top FROM bids WHERE item_id=$1', [id]);
    const minBase = Math.max(agg.rows[0]?.top || 0, item.start_price);
    const minReq = minBase + (item.min_increment || 1);
    if (!Number.isFinite(amount) || amount < minReq) throw new Error(`Bid must be >= ${minReq}`);

    await pool.query('INSERT INTO bids(item_id,bidder,amount) VALUES($1,$2,$3)', [id, bidder||'Ẩn danh', amount]);
    res.redirect(`/item/${id}`);
  } catch (e) { next(e); }
});

// Upload form
app.get('/admin/upload', (req,res)=> res.render('upload'));

// Handle upload
app.post('/admin/upload', upload.array('images', 12), async (req,res,next)=>{
  try {
    const { title, description, start_price, min_increment, end_time } = req.body;
    if (!req.files?.length) throw new Error('No images uploaded');

    const id = nanoid(10);
    let order=0, firstPath=null;

    for (const f of req.files) {
      const ext = f.mimetype.split('/')[1] || 'bin';
      const objectName = `items/${id}/${Date.now()}_${nanoid(6)}.${ext}`;
      const { error } = await supabase.storage.from('images').upload(objectName, f.buffer, { contentType:f.mimetype });
      if (error) throw error;

      if (!firstPath) firstPath = objectName;
      await pool.query('INSERT INTO images(item_id,image_path,sort_order) VALUES($1,$2,$3)', [id, objectName, order++]);
    }

    await pool.query(
      `INSERT INTO items(id,title,description,image_path,start_price,min_increment,end_time,status,owner_id)
       VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
      [id, title.trim(), description.trim(), firstPath, parseFloat(start_price)||0, parseFloat(min_increment)||1, end_time?new Date(end_time).toISOString():null, req.session.user?.id||null]
    );

    res.redirect(`/item/${id}`);
  } catch(e){ next(e); }
});

// Static pages
app.get('/about',(req,res)=>res.render('about'));
app.get('/terms',(req,res)=>res.render('terms'));
app.use((req,res)=>res.status(404).render('404'));

// Error handler
app.use((err,req,res,next)=>{
  console.error('❌',err.message);
  res.status(500).send(err.message||'Internal Error');
});

// ---------- BOOT ----------
const port = process.env.PORT || 3000;
app.listen(port, ()=> console.log(`✅ App on http://localhost:${port}`));
