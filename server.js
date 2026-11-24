const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) { console.error('ADMIN_PASSWORD env var is required'); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || ADMIN_PASSWORD;

// ---------- storage (JSON file on the Railway volume) ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'db.json');
let db = { servers: [], clients: [], settings: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
db.settings = db.settings || {};
const save = () => { fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db, null, 2)); fs.renameSync(DB_FILE + '.tmp', DB_FILE); };
const rid = (n = 8) => crypto.randomBytes(n).toString('hex');

// ---------- auth ----------
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const makeToken = () => { const exp = String(Date.now() + 7 * 864e5); return exp + '.' + sign(exp); };
const validToken = t => {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!sig || Date.now() > +exp) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const getCookie = (req, n) => (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(p => p[0] === n)?.[1];
const tries = {};
const auth = (req, res, next) => validToken(getCookie(req, 'sid')) ? next() : res.status(401).json({ error: 'نیاز به ورود' });

// ---------- 3x-ui API client ----------
const sessions = {};
async function xuiLogin(s) {
  const r = await fetch(s.url + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: s.username, password: s.password }),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.success) throw new Error('ورود به پنل 3x-ui ناموفق بود: ' + (j.msg || r.status));
  const ck = (r.headers.getSetCookie ? r.headers.getSetCookie() : []).map(c => c.split(';')[0]).join('; ');
  sessions[s.id] = ck;
  return ck;
}
async function xui(s, p, body) {
  for (let i = 0; i < 2; i++) {
    const ck = sessions[s.id] || await xuiLogin(s);
    const opt = body
      ? { method: 'POST', headers: { Cookie: ck, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body) }
      : { headers: { Cookie: ck } };
    const r = await fetch(s.url + p, opt);
    let j = null; try { j = JSON.parse(await r.text()); } catch {}
    if (!j) { delete sessions[s.id]; continue; } // session expired or wrong path -> re-login once
    if (!j.success) throw new Error(j.msg || 'خطا از پنل');
    return j.obj;
  }
  throw new Error('پاسخ نامعتبر از پنل. آدرس و webBasePath را بررسی کن.');
}

function buildLink(s, ib, c) {
  if (ib.protocol !== 'vless') throw new Error('فعلاً فقط inbound از نوع vless پشتیبانی میشود');
  const st = JSON.parse(ib.streamSettings || '{}');
  const host = s.host || new URL(s.url).hostname;
  const p = new URLSearchParams({ type: st.network || 'tcp', security: st.security || 'none', encryption: 'none' });
  if (c.flow) p.set('flow', c.flow);
  if (st.security === 'reality') {
    const r = st.realitySettings || {}, rs = r.settings || {};
    p.set('pbk', rs.publicKey || ''); p.set('fp', rs.fingerprint || 'chrome');
    p.set('sni', (r.serverNames || [])[0] || ''); p.set('sid', (r.shortIds || [])[0] || '');
    if (rs.spiderX) p.set('spx', rs.spiderX);
  }
  if (st.security === 'tls') p.set('sni', st.tlsSettings?.serverName || host);
  if (st.network === 'ws') { p.set('path', st.wsSettings?.path || '/'); p.set('host', st.wsSettings?.headers?.Host || ''); }
  if (st.network === 'grpc') p.set('serviceName', st.grpcSettings?.serviceName || '');
  return `vless://${c.id}@${host}:${ib.port}?${p}#${encodeURIComponent(ib.remark + '-' + c.email)}`;
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
// Panel domain priority: saved in panel > PANEL_DOMAIN env > Railway's own domain > current request host
const baseUrl = req => {
  const d = (db.settings.domain || process.env.PANEL_DOMAIN || process.env.RAILWAY_PUBLIC_DOMAIN || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
  return d ? 'https://' + d : `${req.protocol}://${req.get('host')}`;
};
const withSub = (req, c) => ({ ...c, subLink: c.subId ? `${baseUrl(req)}/sub/${c.subId}` : '' });
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const wrap = fn => (req, res) => fn(req, res).catch(e => res.status(400).json({ error: e.message }));
const findServer = id => db.servers.find(s => s.id === id) || (() => { throw new Error('سرور پیدا نشد'); })();

app.post('/api/login', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.ip;
  const t = tries[ip] = (tries[ip] || []).filter(x => Date.now() - x < 6e5);
  if (t.length >= 8) return res.status(429).json({ error: 'تلاش زیاد. چند دقیقه بعد دوباره امتحان کن.' });
  if (req.body.password !== ADMIN_PASSWORD) { t.push(Date.now()); return res.status(401).json({ error: 'رمز اشتباه است' }); }
  res.setHeader('Set-Cookie', `sid=${makeToken()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`);
  res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json({ ok: true }));

app.get('/api/servers', auth, (req, res) => res.json(db.servers.map(({ password, ...s }) => s)));
app.post('/api/servers', auth, wrap(async (req, res) => {
  const { name, url, username, password, host, subUrl } = req.body;
  if (!name || !url || !username || !password) throw new Error('نام، آدرس، یوزرنیم و پسورد لازم است');
  const s = { id: rid(4), name, url: url.replace(/\/+$/, ''), username, password, host: host || '', subUrl: subUrl || '' };
  await xuiLogin(s); // verify before saving
  db.servers.push(s); save();
  res.json({ id: s.id });
}));
app.delete('/api/servers/:id', auth, (req, res) => {
  db.servers = db.servers.filter(s => s.id !== req.params.id); save(); res.json({ ok: true });
});
app.get('/api/servers/:id/inbounds', auth, wrap(async (req, res) => {
  const list = await xui(findServer(req.params.id), '/panel/api/inbounds/list');
  res.json(list.map(i => ({ id: i.id, remark: i.remark, protocol: i.protocol, port: i.port, enable: i.enable })));
}));

app.get('/api/settings', auth, (req, res) => res.json({
  domain: db.settings.domain || '', effective: baseUrl(req),
  auto: process.env.PANEL_DOMAIN || process.env.RAILWAY_PUBLIC_DOMAIN || '',
}));
app.post('/api/settings', auth, (req, res) => {
  db.settings.domain = String(req.body.domain || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  save(); res.json({ effective: baseUrl(req) });
});
// Public subscription endpoint (served on the panel's own domain, no login needed)
app.get('/sub/:subId', (req, res) => {
  const c = db.clients.find(x => x.subId === req.params.subId);
  if (!c || (c.expiry && Date.now() > c.expiry)) return res.status(404).send('not found');
  res.set({
    'Content-Type': 'text/plain; charset=utf-8',
    'Profile-Update-Interval': '12',
    'Subscription-Userinfo': `upload=0; download=0; total=${Math.round((c.gb || 0) * 1024 ** 3)}; expire=${c.expiry ? Math.floor(c.expiry / 1000) : 0}`,
  });
  res.send(Buffer.from(c.link).toString('base64'));
});
app.get('/api/clients', auth, (req, res) => res.json(db.clients.map(c => withSub(req, c))));
app.post('/api/clients', auth, wrap(async (req, res) => {
  const { serverId, inboundId, name, gb, days } = req.body;
  const s = findServer(serverId);
  const list = await xui(s, '/panel/api/inbounds/list');
  const ib = list.find(i => i.id === Number(inboundId));
  if (!ib) throw new Error('inbound پیدا نشد');
  const existing = (JSON.parse(ib.settings || '{}').clients || [])[0] || {};
  const c = {
    id: crypto.randomUUID(), email: `${(name || 'user').replace(/\s+/g, '_')}-${rid(2)}`,
    flow: existing.flow || '', limitIp: 0, totalGB: Math.round((+gb || 0) * 1024 ** 3),
    expiryTime: +days ? Date.now() + days * 864e5 : 0, enable: true, tgId: '', subId: rid(8), reset: 0,
  };
  await xui(s, '/panel/api/inbounds/addClient', { id: String(ib.id), settings: JSON.stringify({ clients: [c] }) });
  const rec = {
    id: c.id, serverId, inboundId: ib.id, email: c.email, link: buildLink(s, ib, c),
    subId: c.subId,
    gb: +gb || 0, expiry: c.expiryTime, created: Date.now(),
  };
  db.clients.push(rec); save();
  res.json(withSub(req, rec));
}));
app.delete('/api/clients/:id', auth, wrap(async (req, res) => {
  const rec = db.clients.find(c => c.id === req.params.id);
  if (!rec) throw new Error('کاربر پیدا نشد');
  const s = db.servers.find(x => x.id === rec.serverId);
  if (s) { try { await xui(s, `/panel/api/inbounds/${rec.inboundId}/delClient/${rec.id}`, {}); } catch (e) { if (!req.query.force) throw e; } }
  db.clients = db.clients.filter(c => c.id !== rec.id); save();
  res.json({ ok: true });
}));

app.listen(PORT, '0.0.0.0', () => console.log('panel on', PORT));
