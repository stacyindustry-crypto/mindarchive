// The Mind Archive backend. Run: npm install && ADMIN_EMAILS=you@site.com ADMIN_PASSWORD=... npm start
const path = require('path'), crypto = require('crypto');
const express = require('express'), multer = require('multer'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client'); // Turso cloud database (or a local file when TURSO_DATABASE_URL is not set)

const db = createClient({ url: process.env.TURSO_DATABASE_URL || 'file:' + (process.env.DB_PATH || 'archive.db'), authToken: process.env.TURSO_AUTH_TOKEN });
(async () => {
await db.executeMultiple(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,email TEXT UNIQUE,hash TEXT,role TEXT DEFAULT 'member',status TEXT DEFAULT 'pending',created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS pages(id INTEGER PRIMARY KEY,pos REAL,type TEXT,title TEXT,body TEXT,mime TEXT,data BLOB);
CREATE TABLE IF NOT EXISTS works(id INTEGER PRIMARY KEY,user_id INT,kind TEXT,title TEXT,body TEXT,filename TEXT,mime TEXT,data BLOB,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS gallery(id INTEGER PRIMARY KEY,user_id INT,title TEXT,caption TEXT,mime TEXT,data BLOB,status TEXT DEFAULT 'pending',created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY,name TEXT,email TEXT,title TEXT,description TEXT,filename TEXT,mime TEXT,data BLOB,status TEXT DEFAULT 'pending',created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS newsletters(id INTEGER PRIMARY KEY,title TEXT,summary TEXT,url TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);`);
const all = async (s, ...a) => (await db.execute({ sql: s, args: a })).rows.map(r => ({ ...r })), one = async (s, ...a) => (await all(s, ...a))[0], run = (s, ...a) => db.execute({ sql: s, args: a });
const setting = async (k, v) => { if (v !== undefined) await run('INSERT INTO settings VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, v); return (await one('SELECT v FROM settings WHERE k=?', k))?.v; };
let SECRET = await setting('secret'); if (!SECRET) SECRET = await setting('secret', crypto.randomBytes(32).toString('hex'));
if ((await setting('portal')) === undefined) await setting('portal', process.env.PORTAL_URL || '');

// Admin (editor) accounts come from ADMIN_EMAILS (comma separated) and are created approved.
const pw = process.env.ADMIN_PASSWORD || 'ChangeMe!2026';
for (const e of (process.env.ADMIN_EMAILS || 'admin@mindarchive.com').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)) {
  if (!await one('SELECT 1 x FROM users WHERE email=?', e)) await run("INSERT INTO users(name,email,hash,role,status) VALUES('Editor',?,?,'admin','approved')", e, bcrypt.hashSync(pw, 10));
  else await run("UPDATE users SET role='admin',status='approved' WHERE email=?", e); // anyone already registered with a listed email becomes an editor (keeps their own password)
}
if (!process.env.ADMIN_PASSWORD) console.warn('Using the default admin password. Set ADMIN_PASSWORD before going live.');

if (!(await one('SELECT 1 x FROM pages'))) for (const [i, [t, a, b]] of [
  ['cover', 'The Mind Archive', 'Issue No. 1\n\nEssays, fragments and field notes from people who think for a living, and for fun.'],
  ['text', 'Editor’s note', 'Welcome to the archive. Every issue is a room and every page a shelf.\n\nSign in as an editor to replace these sample pages: upload images, import a PDF, or write pages directly.'],
  ['text', 'On slow thinking', 'Some ideas arrive like coffee left to steep: unhurried, darker with time. This is a placeholder essay. Replace it from the Editors’ room, under Book pages.'],
  ['cover', 'To be continued', 'Thank you for reading.']
].entries()) await run('INSERT INTO pages(pos,type,title,body) VALUES(?,?,?,?)', i, t, a, b);

// ---------- helpers ----------
const tok = q => /(?:^|; )t=([^;]+)/.exec(q.headers.cookie || '')?.[1];
const who = async q => { try { const u = await one('SELECT id,name,email,role,status FROM users WHERE id=?', jwt.verify(tok(q), SECRET).id); return u?.status === 'approved' ? u : null; } catch { return null; } };
const need = role => async (q, s, n) => {
  const u = await who(q);
  if (!u) return s.status(401).json({ error: 'Please sign in' });
  if (role && u.role !== role) return s.status(403).json({ error: 'Editors only' });
  q.user = u; n();
};
const hits = new Map();
const limit = (n, ms) => (q, s, nx) => {
  const k = q.ip + q.path, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < ms);
  if (a.length >= n) return s.status(429).json({ error: 'Too many attempts. Try again later' });
  a.push(now); hits.set(k, a); nx();
};
const IMG = /^image\/(jpeg|png|webp|gif)$/, DOC = /^(image\/(jpeg|png|webp|gif)|application\/(pdf|msword|vnd\.openxmlformats-officedocument\.wordprocessingml\.document)|text\/plain)$/;
const up = (re = DOC) => multer({ storage: multer.memoryStorage(), limits: { fileSize: 8e6, files: 1 }, fileFilter: (q, f, cb) => re.test(f.mimetype) ? cb(null, true) : cb(new Error('Unsupported file type')) }).single('file');
const clean = (s, n = 200) => String(s ?? '').trim().slice(0, n);
const file = q => q.file ? [q.file.originalname.slice(0, 120), q.file.mimetype, q.file.buffer] : [null, null, null];
const bad = (s, m) => s.status(400).json({ error: m });
const mail = e => /^\S+@\S+\.\S+$/.test(e);
const send = (s, r, inline) => {
  if (!r?.data) return s.sendStatus(404);
  if (!inline) s.attachment(r.filename || 'file');
  s.type(r.mime).set({ 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, max-age=300' }).send(Buffer.from(r.data));
};

const app = express();
['get', 'post', 'delete'].forEach(m => { const o = app[m].bind(app); app[m] = (p, ...h) => o(p, ...h.map(f => (q, s, n) => Promise.resolve(f(q, s, n)).catch(n))); }); // send async errors to the error handler
app.set('trust proxy', 1); // hosts such as Render sit behind a proxy; this keeps per-visitor rate limits and client IPs correct
app.use(express.static(path.join(__dirname, 'public')));

// ---------- auth ----------
app.post('/api/register', limit(10, 36e5), up(), async (q, s) => {
  const name = clean(q.body.name, 80), email = clean(q.body.email).toLowerCase(), p = String(q.body.password || '');
  if (!name || !mail(email) || p.length < 8) return bad(s, 'Enter your name, a valid email and a password of at least 8 characters');
  if (await one('SELECT 1 x FROM users WHERE email=?', email)) return s.status(409).json({ error: 'That email is already registered' });
  await run('INSERT INTO users(name,email,hash) VALUES(?,?,?)', name, email, bcrypt.hashSync(p, 10));
  s.json({ message: 'Request received. An editor will approve your membership soon.' });
});
app.post('/api/login', limit(20, 9e5), up(), async (q, s) => {
  const u = await one('SELECT * FROM users WHERE email=?', clean(q.body.email).toLowerCase());
  if (!u || !bcrypt.compareSync(String(q.body.password || ''), u.hash)) return s.status(401).json({ error: 'Wrong email or password' });
  if (u.status !== 'approved') return s.status(403).json({ error: u.status === 'pending' ? 'Your membership is waiting for approval' : 'Your membership request was declined' });
  s.cookie('t', jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' }), { httpOnly: true, sameSite: 'strict', maxAge: 6048e5, secure: process.env.NODE_ENV === 'production' });
  s.json({ message: 'Signed in', user: { id: u.id, name: u.name, email: u.email, role: u.role } });
});
app.post('/api/logout', async (q, s) => { s.clearCookie('t'); s.json({ message: 'Signed out' }); });
app.get('/api/me', async (q, s) => s.json({ user: await who(q) }));
app.get('/api/settings', async (q, s) => s.json({ portal: await setting('portal'), substack: SUBSTACK }));

// ---------- magazine book ----------
app.get('/api/pages', async (q, s) => s.json(await all('SELECT id,type,title,body,mime IS NOT NULL img FROM pages ORDER BY pos')));
app.get('/api/pages/:id/image', async (q, s) => send(s, await one('SELECT mime,data FROM pages WHERE id=?', +q.params.id), 1));

// ---------- member works & notes ----------
app.get('/api/works', need(), async (q, s) => s.json(await all('SELECT w.id,w.kind,w.title,w.body,w.filename,w.user_id,w.created,u.name author FROM works w LEFT JOIN users u ON u.id=w.user_id ORDER BY w.id DESC')));
app.post('/api/works', need(), up(), async (q, s) => {
  const t = clean(q.body.title); if (!t) return bad(s, 'Add a title');
  const [n, m, d] = file(q);
  await run('INSERT INTO works(user_id,kind,title,body,filename,mime,data) VALUES(?,?,?,?,?,?,?)', q.user.id, q.body.kind === 'note' ? 'note' : 'work', t, clean(q.body.body, 8000), n, m, d);
  s.json({ message: 'Saved to the archive' });
});
app.get('/api/works/:id/file', need(), async (q, s) => send(s, await one('SELECT filename,mime,data FROM works WHERE id=?', +q.params.id)));
app.delete('/api/works/:id', need(), async (q, s) => { await run('DELETE FROM works WHERE id=? AND (user_id=? OR ?)', +q.params.id, q.user.id, q.user.role === 'admin' ? 1 : 0); s.json({ message: 'Deleted' }); });

// ---------- gallery ----------
app.get('/api/gallery', async (q, s) => s.json(await all("SELECT g.id,g.title,g.caption,u.name author FROM gallery g LEFT JOIN users u ON u.id=g.user_id WHERE g.status='approved' ORDER BY g.id DESC")));
app.get('/api/gallery/:id/image', async (q, s) => { const r = await one('SELECT mime,data,status FROM gallery WHERE id=?', +q.params.id); send(s, r && (r.status === 'approved' || await who(q)) ? r : null, 1); });
app.post('/api/gallery', need(), up(IMG), async (q, s) => {
  const [, m, d] = file(q); if (!d) return bad(s, 'Choose an image (JPG, PNG, WebP or GIF)');
  const a = q.user.role === 'admin';
  await run('INSERT INTO gallery(user_id,title,caption,mime,data,status) VALUES(?,?,?,?,?,?)', q.user.id, clean(q.body.title) || 'Untitled', clean(q.body.caption, 500), m, d, a ? 'approved' : 'pending');
  s.json({ message: a ? 'Published to the gallery' : 'Uploaded. An editor will review it before it appears' });
});

// ---------- public submissions ----------
app.post('/api/submissions', limit(5, 36e5), up(), async (q, s) => {
  const b = q.body; if (b.website) return s.json({ message: 'Thank you!' }); // honeypot
  const name = clean(b.name, 80), email = clean(b.email), title = clean(b.title);
  if (!name || !mail(email) || !title) return bad(s, 'Add your name, a valid email and a title');
  const [n, m, d] = file(q);
  await run('INSERT INTO submissions(name,email,title,description,filename,mime,data) VALUES(?,?,?,?,?,?,?)', name, email, title, clean(b.description, 4000), n, m, d);
  s.json({ message: 'Thank you. Your work is with our editors for review.' });
});

// ---------- newsletter (Substack) ----------
// Set SUBSTACK_URL (for example https://yourname.substack.com). Sign-ups use Substack's own embedded form; posts come from its public RSS feed.
const SUBSTACK = (process.env.SUBSTACK_URL || '').trim().replace(/\/+$/, '');
const dec = x => x.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&amp;/g, '&');
const tag = (x, t) => { const m = new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`).exec(x); return m ? dec(m[1].replace(/^\s*<!\[CDATA\[|\]\]>\s*$/g, '').replace(/<[^>]+>/g, '').trim()) : ''; };
app.get('/api/newsletters', async (q, s) => s.json(await all('SELECT id,title,summary,url,created FROM newsletters ORDER BY created DESC,id DESC')));

// ---------- admin ----------
const A = need('admin');
app.get('/api/admin/all', A, async (q, s) => s.json({
  users: await all('SELECT id,name,email,role,status FROM users ORDER BY id DESC'),
  subs: await all('SELECT id,name,email,title,description,filename,status FROM submissions ORDER BY id DESC'),
  gallery: await all('SELECT g.id,g.title,g.status,u.name author FROM gallery g LEFT JOIN users u ON u.id=g.user_id ORDER BY g.id DESC')
}));
app.get('/api/admin/submissions/:id/file', A, async (q, s) => send(s, await one('SELECT filename,mime,data FROM submissions WHERE id=?', +q.params.id)));
app.post('/api/admin/settings', A, up(), async (q, s) => {
  const p = clean(q.body.portal, 500); if (p && !/^https?:\/\//.test(p)) return bad(s, 'The portal link must start with http:// or https://');
  await setting('portal', p); s.json({ message: 'Portal link saved' });
});
app.post('/api/admin/:t(users|submissions|gallery)/:id/:st(approved|rejected)', A, async (q, s) => {
  if (q.params.t === 'users' && +q.params.id === q.user.id) return bad(s, 'You cannot change your own status');
  await run(`UPDATE ${q.params.t} SET status=? WHERE id=?`, q.params.st, +q.params.id); s.json({ message: 'Marked ' + q.params.st });
});
app.delete('/api/admin/:t(submissions|gallery|pages|newsletters)/:id', A, async (q, s) => { await run(`DELETE FROM ${q.params.t} WHERE id=?`, +q.params.id); s.json({ message: 'Deleted' }); });
app.post('/api/admin/pages', A, up(IMG), async (q, s) => {
  const [, m, d] = file(q), t = ['image', 'text', 'cover'].includes(q.body.type) ? q.body.type : 'text';
  if (t === 'image' && !d) return bad(s, 'Choose an image for an image page');
  await run('INSERT INTO pages(pos,type,title,body,mime,data) VALUES((SELECT IFNULL(MAX(pos),0)+1 FROM pages),?,?,?,?,?)', t, clean(q.body.title), clean(q.body.body, 4000), m, d);
  s.json({ message: 'Page added to the book' });
});
app.post('/api/admin/pages/:id/:d(up|down)', A, async (q, s) => {
  const id = +q.params.id, p = await one('SELECT pos FROM pages WHERE id=?', id), u = q.params.d === 'up';
  if (!p) return s.sendStatus(404);
  const n = await one(`SELECT id,pos FROM pages WHERE pos${u ? '<' : '>'}? ORDER BY pos ${u ? 'DESC' : 'ASC'} LIMIT 1`, p.pos);
  if (n) { await run('UPDATE pages SET pos=? WHERE id=?', n.pos, id); await run('UPDATE pages SET pos=? WHERE id=?', p.pos, n.id); }
  s.json({ message: 'Moved' });
});

app.post('/api/admin/newsletters', A, up(), async (q, s) => {
  const t = clean(q.body.title), u = clean(q.body.url, 500);
  if (!t || !/^https?:\/\//.test(u)) return bad(s, 'Add a title and a link that starts with http:// or https://');
  await run('INSERT INTO newsletters(title,summary,url) VALUES(?,?,?)', t, clean(q.body.summary, 600), u);
  s.json({ message: 'Issue added to the newsletter' });
});

app.post('/api/admin/newsletters/import', A, async (q, s) => {
  if (!/^https:\/\//.test(SUBSTACK)) return bad(s, 'Set SUBSTACK_URL (for example https://yourname.substack.com) and restart the site');
  try {
    const r = await fetch(SUBSTACK + '/feed', { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MindArchive/1.0)', Accept: 'application/rss+xml,text/xml' } });
    if (!r.ok) return bad(s, `Substack answered with status ${r.status}. Check SUBSTACK_URL`);
    let added = 0;
    for (const x of (await r.text()).split('<item>').slice(1, 21).reverse()) {
      const url = tag(x, 'link'), title = tag(x, 'title'), d = new Date(tag(x, 'pubDate'));
      if (!title || !/^https:\/\//.test(url) || await one('SELECT 1 x FROM newsletters WHERE url=?', url)) continue;
      await run('INSERT INTO newsletters(title,summary,url,created) VALUES(?,?,?,COALESCE(?,CURRENT_TIMESTAMP))', title, tag(x, 'description').slice(0, 600), url, isNaN(d) ? null : d.toISOString().slice(0, 19).replace('T', ' '));
      added++;
    }
    s.json({ message: added ? `Imported ${added} new post${added > 1 ? 's' : ''} from Substack` : 'Already up to date' });
  } catch (e) { bad(s, 'Could not reach Substack: ' + e.message); }
});

app.use((e, q, s, n) => s.status(400).json({ error: e.message || 'Something went wrong' }));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`The Mind Archive is running at http://localhost:${port}`));
})().catch(e => { console.error('Startup failed:', e); process.exit(1); });
