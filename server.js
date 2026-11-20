/* Prac360 server — runs the app for a whole team, on a private network or on the internet.
 * Serves the Prac360 app and keeps one shared copy of its data, so every browser sees the same logins, practices and
 * records, with live updates. No extra packages needed — Node.js 18 or newer.
 *
 * Security (v2, safe to put on the internet with demo / synthetic data):
 *  - Sign-in is checked here on the server (same PBKDF2-SHA-256 hashes the app uses) and gives the browser a
 *    session token. Two-step verification (TOTP or recovery code) is also checked here.
 *  - Nobody receives password hashes, two-step secrets, recovery codes or reset codes of other people.
 *  - Practice data (patients, accounts, diary …) is only sent to signed-in people with access to that practice.
 *  - Every change is checked: people who are not signed in can only add a registration or a login request;
 *    only Prac360 administrators can give Prac360 staff access; passwords of other people can only be changed by
 *    their practice owner / administrator or Prac360 staff.
 *  - Repeated wrong passwords are slowed down and blocked per email and per internet address.
 *  - HTTPS: put it behind a host that gives HTTPS (Render, Railway, Fly.io, Cloudflare Tunnel …) and set
 *    FORCE_HTTPS=1, or add certs/key.pem + certs/cert.pem.
 *  - Daily backups of the data file (last 14 days) in data/backups.
 *
 *   node server.js              → http://<this-computer>:8360
 *   PORT, HOST, DATA_DIR, FORCE_HTTPS=1, SESSION_HOURS (default 12) can be set as environment variables. */
'use strict';
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const PORT = +(process.env.PORT || 8360); const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname; const PUB = fs.existsSync(path.join(ROOT, 'public', 'index.html')) ? path.join(ROOT, 'public') : ROOT;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data'); const FILE = path.join(DATA_DIR, 'prac360-data.json');
const SFILE = path.join(DATA_DIR, 'sessions.json'); const BDIR = path.join(DATA_DIR, 'backups');
const FORCE_HTTPS = process.env.FORCE_HTTPS === '1'; const SESSION_MS = (+process.env.SESSION_HOURS || 12) * 3600e3;
const MAX_BODY = 60 * 1024 * 1024, MAX_ANON_BODY = 3 * 1024 * 1024;
const PKEY = 'clinprac360-platform-v1';
fs.mkdirSync(DATA_DIR, { recursive: true }); fs.mkdirSync(BDIR, { recursive: true });

// ------------------------------------------------------------------ storage
let kv = {}; try { kv = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { kv = {}; }
const seedFile = path.join(ROOT, 'seed-data.json');
if (!kv[PKEY] && fs.existsSync(seedFile)) { try { kv = JSON.parse(fs.readFileSync(seedFile, 'utf8')); console.log('  Started with the demo data from seed-data.json'); } catch (e) { /* ignore */ } }
let saveT = null; const writeNow = () => { const tmp = FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(kv)); fs.renameSync(tmp, FILE); };
const saveSoon = () => { clearTimeout(saveT); saveT = setTimeout(writeNow, 400); };
let sessions = {}; try { sessions = JSON.parse(fs.readFileSync(SFILE, 'utf8')); } catch (e) { sessions = {}; }
let sesT = null; const saveSessions = () => { clearTimeout(sesT); sesT = setTimeout(() => { const now = Date.now(); for (const t in sessions) if (sessions[t].exp < now) delete sessions[t]; try { fs.writeFileSync(SFILE, JSON.stringify(sessions)); } catch (e) { /* ignore */ } }, 500); };
const backup = () => { try { const day = new Date().toISOString().slice(0, 10); const f = path.join(BDIR, `prac360-${day}.json`); if (!fs.existsSync(f) && fs.existsSync(FILE)) fs.copyFileSync(FILE, f);
  fs.readdirSync(BDIR).filter((x) => /^prac360-\d{4}-\d\d-\d\d\.json$/.test(x)).sort().slice(0, -14).forEach((x) => fs.unlinkSync(path.join(BDIR, x))); } catch (e) { console.error('backup failed', e.message); } };
setInterval(backup, 3600e3); setTimeout(backup, 5000);

// ------------------------------------------------------------------ platform helpers
const plat = () => { try { return kv[PKEY] ? JSON.parse(kv[PKEY]) : null; } catch (e) { return null; } };
const SECRET = ['pwHash', 'pwSalt', 'mfa', 'codes', 'recovery', 'pinHash', 'pinSalt', 'tempPw', 'resetToken', 'secret'];
const accOf = (p, id) => (p && p.accounts || []).find((a) => a.id === id);
const byEmail = (p, e) => (p && p.accounts || []).find((a) => a.email === String(e || '').trim().toLowerCase());
const grantsOf = (p, id) => (p && p.grants || []).filter((g) => g.accountId === id);
const isStaff = (p, id) => grantsOf(p, id).some((g) => g.scope === 'platform');
const isPlatAdmin = (p, id) => grantsOf(p, id).some((g) => g.scope === 'platform' && ['superadmin', 'admin'].includes(g.role));
const orgsManaged = (p, id) => grantsOf(p, id).filter((g) => g.scope === 'org' && ['owner', 'admin', 'manager'].includes(g.role)).map((g) => g.orgId);
const dsManaged = (p, id) => { const out = new Set(); grantsOf(p, id).forEach((g) => { if (g.scope === 'dataset' && g.datasetRole === 'manager') out.add(g.datasetId); if (g.scope === 'org' && (['owner', 'admin', 'manager'].includes(g.role) || g.datasetRole === 'manager')) (p.datasets || []).filter((d) => d.orgId === g.orgId).forEach((d) => out.add(d.id)); }); return out; };
const canManageAcc = (p, by, target) => { if (by === target || isStaff(p, by)) return true; const mine = orgsManaged(p, by); const ds = dsManaged(p, by);
  return grantsOf(p, target).some((g) => (g.scope === 'org' && mine.includes(g.orgId)) || (g.scope === 'dataset' && ds.has(g.datasetId))); };
const dsForKey = (p, k) => (p && p.datasets || []).filter((d) => d.storageKey && (k === d.storageKey || k.startsWith(d.storageKey + '-') || k.startsWith(d.storageKey + ':'))).sort((a, b) => b.storageKey.length - a.storageKey.length)[0];
const canKey = (p, who, k) => { if (!who || who.level !== 'full') return false; if (k === PKEY) return true; if (/^p360-live-/.test(k)) return true;
  const a = accOf(p, who.acc); if (!a || a.status !== 'active') return false; if (a.demoAll || isStaff(p, who.acc)) return true;
  const ds = dsForKey(p, k); if (!ds) return false; const g = grantsOf(p, who.acc);
  if (g.some((x) => (x.scope === 'org' && x.orgId === ds.orgId) || (x.scope === 'dataset' && x.datasetId === ds.id))) return true;
  return (p.links || []).some((l) => l.datasetId === ds.id && l.status === 'approved' && g.some((x) => x.scope === 'org' && x.orgId === l.bureauOrgId)); };
const strip = (a, keepOwn) => { const o = Object.assign({}, a); SECRET.forEach((f) => { if (f in o) { if (keepOwn && f === 'mfa' && o.mfa) o.mfa = Object.assign({}, o.mfa); else if (!keepOwn) delete o[f]; } }); return o; };
const mailKey = (m) => crypto.createHash('sha1').update(JSON.stringify(m)).digest('hex');
const anonMail = {}; // mail id → client id that created it (so the browser that registers can read its own code)
const created = {}; // client id → { accounts:Set, orgs:Set, at }
const cr = (c) => (created[c] = created[c] || { accounts: new Set(), orgs: new Set(), invites: new Set(), at: Date.now() });

const emptyLike = (o, keep) => Object.fromEntries(Object.entries(o).map(([k, x]) => [k, keep.includes(k) ? x : Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x]));
// What one browser may see of the platform record
const view = (p, who, client) => { if (!p) return null; const v = JSON.parse(JSON.stringify(p)); const me = who && accOf(p, who.acc);
  if (who && who.level === 'full') {
    v.accounts = v.accounts.map((a) => (a.id === who.acc ? a : strip(a)));
    const staff = isStaff(p, who.acc) || (me && me.demoAll); if (!staff) v.mailbox = (v.mailbox || []).filter((m) => me && m.to === me.email);
    return v; }
  // not signed in yet (or only the password step is done): the minimum for sign-in, registration and login requests
  const c = created[client] || { accounts: new Set(), orgs: new Set() };
  const out = { version: v.version, policy: v.policy, demoIds: v.demoIds, notices: [],
    orgs: (v.orgs || []).map((o) => (c.orgs.has(o.id) ? o : { id: o.id, type: o.type, name: o.type === 'dealer' ? o.name : undefined, code: o.type === 'dealer' ? o.code : undefined, status: o.status })),
    datasets: (v.datasets || []).filter((d) => c.orgs.has(d.orgId)), grants: (v.grants || []).filter((g) => c.accounts.has(g.accountId)), links: [], invites: [],
    accounts: (v.accounts || []).map((a) => { if (who && a.id === who.acc) { const o = strip(a, true); if (!a.demo && o.mfa) { delete o.mfa.secret; delete o.mfa.recovery; } delete o.pwHash; delete o.pwSalt; return o; }
      if (c.accounts.has(a.id)) return a; return a.demo ? { id: a.id, email: a.email, name: a.name, status: a.status, demo: true } : { id: a.id, status: a.status }; }),
    authLog: [], accessLog: [], mailbox: (v.mailbox || []).filter((m) => anonMail[mailKey(m)] === client), loginRequests: (v.loginRequests || []).filter((r) => c.loginReq && c.loginReq.has(r.id)),
    bill: v.bill ? emptyLike(v.bill, ['rates', 'seq', 'seeded']) : undefined, tsvc: v.tsvc ? emptyLike(v.tsvc, ['seeded', 'rev']) : undefined, shr: v.shr ? emptyLike(v.shr, []) : undefined, trainReminders: [] };
  Object.keys(out).forEach((k) => out[k] === undefined && delete out[k]); return out; };

// Merge a changed platform record from one browser into the server copy, keeping only what that person may change
const ARR_ID = ['orgs', 'datasets', 'accounts', 'grants', 'links', 'invites', 'notices', 'loginRequests', 'trainReminders'];
const ARR_LOG = ['authLog', 'accessLog', 'mailbox', 'adminLog'];
const LOG_CAP = 3000;
const mergePlat = (cur, inc, who, client, seen) => {
  const full = who && who.level === 'full'; const by = who && who.acc; const admin = full && isPlatAdmin(cur, by); const c = cr(client); const out = JSON.parse(JSON.stringify(cur)); let refused = 0;
  const known = (arr) => new Set((seen && seen[arr]) || []);
  ARR_ID.forEach((arr) => { const sv = out[arr] = out[arr] || []; const iv = Array.isArray(inc[arr]) ? inc[arr] : null; if (!iv) return; const byId = new Map(sv.map((x) => [x.id, x]));
    iv.forEach((x) => { if (!x || !x.id) return; const old = byId.get(x.id);
      if (!old) { // a new item
        if (!full) { // not signed in: only registrations, login requests and invitation sign-ups
          if (arr === 'accounts') { if (byEmail(out, x.email) || x.demoAll || x.demo || !['pending-verify', 'pending', 'active'].includes(x.status)) { refused++; return; } c.accounts.add(x.id); }
          else if (arr === 'orgs') { if (x.type === 'platform' || x.type === 'dealer' && x.status === 'active') { refused++; return; } c.orgs.add(x.id); }
          else if (arr === 'datasets') { if (!c.orgs.has(x.orgId)) { refused++; return; } }
          else if (arr === 'grants') { const inv = (out.invites || []).find((i) => c.invites.has(i.id) && i.orgId === x.orgId);
            const invD = (out.invites || []).find((i) => c.invites.has(i.id) && i.datasetId && i.datasetId === x.datasetId);
            const okOrg = c.accounts.has(x.accountId) && ((x.scope === 'org' && (c.orgs.has(x.orgId) || (inv && (!inv.orgRole || inv.orgRole === x.role)))) || (x.scope === 'dataset' && !!invD));
            const okPlat = x.scope === 'platform' && c.accounts.has(x.accountId) && (out.invites || []).some((i) => c.invites.has(i.id) && i.platformRole === x.role);
            if (!okOrg && !okPlat) { refused++; return; } }
          else if (arr === 'loginRequests') { c.loginReq = c.loginReq || new Set(); c.loginReq.add(x.id); }
          else { refused++; return; } }
        else if (arr === 'grants' && x.scope === 'platform' && !admin) { refused++; return; }
        else if (arr === 'accounts' && x.demoAll && !admin) { refused++; return; }
        sv.push(x); byId.set(x.id, x); return; }
      // an existing item that changed
      if (JSON.stringify(old) === JSON.stringify(Object.assign({}, old, x))) return;
      if (!full) { const mine = (arr === 'accounts' && c.accounts.has(x.id)) || (arr === 'orgs' && c.orgs.has(x.id)) || (arr === 'datasets' && c.orgs.has(x.orgId)) || (arr === 'loginRequests' && c.loginReq && c.loginReq.has(x.id));
        const own = who && arr === 'accounts' && x.id === by; const invUse = arr === 'invites' && c.invites.has(x.id);
        if (own) { // password done, two-step pending: may only switch on two-step for the first time and record failures
          const next = Object.assign({}, old); ['fails', 'lockedUntil', 'lastLogin'].forEach((f) => { if (f in x) next[f] = x[f]; }); if ((!old.mfa || !old.mfa.enabled) && x.mfa && x.mfa.enabled && x.mfa.secret) { next.mfa = x.mfa; who.upgrade = true; }
          Object.assign(old, next); return; }
        if (invUse) { Object.assign(old, { used: x.used, usedAt: x.usedAt, usedBy: x.usedBy }); return; }
        if (!mine) { refused++; return; } if (x.demoAll || x.demo) { refused++; return; } Object.assign(old, x); return; }
      if (arr === 'grants' && (old.scope === 'platform' || x.scope === 'platform') && !admin) { refused++; return; }
      if (arr === 'accounts') { const next = Object.assign({}, x); const other = x.id !== by; // other people's secrets were never sent, so "missing" means "unchanged"
        SECRET.forEach((f) => { if (!(f in x)) { if (other && f in old) next[f] = old[f]; } else if (other && JSON.stringify(x[f]) !== JSON.stringify(old[f]) && !canManageAcc(out, by, x.id)) { next[f] = old[f]; refused++; } });
        if (x.demoAll && !old.demoAll && !admin) { next.demoAll = old.demoAll; refused++; }
        byId.set(x.id, next); sv[sv.indexOf(old)] = next; return; }
      Object.keys(old).forEach((k) => { if (!(k in x)) delete old[k]; }); Object.assign(old, x); });
    if (full) { // deletions: only items this browser had seen and removed (newer items from others stay)
      const k = known(arr); const keep = new Set(iv.map((x) => x && x.id));
      for (let i = sv.length - 1; i >= 0; i--) { const x = sv[i]; if (k.has(x.id) && !keep.has(x.id)) { if (arr === 'grants' && x.scope === 'platform' && !admin) { refused++; continue; } if (arr === 'accounts' && !canManageAcc(out, by, x.id)) { refused++; continue; } sv.splice(i, 1); } } } });
  ARR_LOG.forEach((arr) => { if (!Array.isArray(inc[arr])) return; const sv = out[arr] = out[arr] || []; const have = new Set(sv.map(mailKey)); let added = 0;
    inc[arr].forEach((x) => { const k = mailKey(x); if (have.has(k)) return; if (!full && ++added > 20) return; sv.push(x); have.add(k); if (arr === 'mailbox' && !full) anonMail[k] = client; });
    if (sv.length > LOG_CAP) out[arr] = sv.slice(-LOG_CAP); });
  // other parts (billing, tariffs, settings …): signed-in people only; a part is replaced only if this browser changed it
  Object.keys(inc).forEach((k) => { if (ARR_ID.includes(k) || ARR_LOG.includes(k)) return; const was = seen && seen.parts && seen.parts[k]; const now = JSON.stringify(inc[k]);
    if (!full) { if (k === 'bill' && inc.bill && out.bill) ['subs', 'usage', 'contacts', 'mandates'].forEach((s) => { const src = inc.bill[s]; if (src && typeof src === 'object' && !Array.isArray(src)) { out.bill[s] = out.bill[s] || {}; Object.keys(src).forEach((oid) => { if (c.orgs.has(oid) && !(oid in out.bill[s])) out.bill[s][oid] = src[oid]; }); } }); return; }
    if (k === 'policy' && !admin && now !== JSON.stringify(cur.policy)) { refused++; return; }
    if (was !== undefined && was === crypto.createHash('sha1').update(now).digest('hex')) return; out[k] = inc[k]; });
  return { out, refused }; };

// ------------------------------------------------------------------ crypto: PBKDF2 like the app, TOTP for two-step
const pbkdf2 = (pw, salt, iter) => new Promise((ok, bad) => crypto.pbkdf2(String(pw), Buffer.from(salt || '', 'hex'), iter || 210000, 32, 'sha256', (e, k) => (e ? bad(e) : ok(k.toString('hex')))));
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const unb32 = (s) => { let bits = 0, val = 0; const out = []; String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '').split('').forEach((ch) => { val = (val << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }); return Buffer.from(out); };
const totp = (secret, t) => { const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(t / 30000))); const h = crypto.createHmac('sha1', unb32(secret)).update(ctr).digest(); const o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1e6)).padStart(6, '0'); };
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const timingEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// ------------------------------------------------------------------ rate limits (wrong passwords, anonymous writes)
const hits = {}; const hit = (k, max, ms) => { const now = Date.now(); const h = (hits[k] = (hits[k] || []).filter((t) => now - t < ms)); h.push(now); return h.length > max; };
const blocked = (k, max, ms) => { const now = Date.now(); return ((hits[k] || []).filter((t) => now - t < ms)).length >= max; };
setInterval(() => { const now = Date.now(); for (const k in hits) { hits[k] = hits[k].filter((t) => now - t < 3600e3); if (!hits[k].length) delete hits[k]; } }, 600e3);

// ------------------------------------------------------------------ sessions
const ipOf = (req) => (String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?');
const tokenOf = (req, u) => { const h = String(req.headers.authorization || ''); return h.startsWith('Bearer ') ? h.slice(7) : (u.searchParams.get('t') || ''); };
const whoOf = (req, u) => { const t = tokenOf(req, u); const s = t && sessions[t]; if (!s || s.exp < Date.now()) return null; const p = plat(); const a = accOf(p, s.acc); if (!a || a.status !== 'active') return null; return Object.assign(s, { token: t }); };
const newSession = (acc, level, req) => { const t = crypto.randomBytes(32).toString('hex'); sessions[t] = { acc, level, exp: Date.now() + (level === 'full' ? SESSION_MS : 10 * 60e3), ip: ipOf(req), at: Date.now() }; saveSessions(); return t; };
const seenOf = {}; // token → ids and part fingerprints this browser was last sent (so stale copies cannot delete newer work)
const remember = (who, client, v) => { const key = (who && who.token) || 'c:' + client; const s = { parts: {} }; ARR_ID.forEach((a) => { s[a] = (v[a] || []).map((x) => x && x.id); });
  Object.keys(v).forEach((k) => { if (!ARR_ID.includes(k) && !ARR_LOG.includes(k)) s.parts[k] = crypto.createHash('sha1').update(JSON.stringify(v[k])).digest('hex'); }); seenOf[key] = s; };

// ------------------------------------------------------------------ live updates (only key names are pushed; each browser fetches what it may see)
const clients = new Set();
const notify = (k, c) => { const data = `data: ${JSON.stringify({ k, c })}\n\n`; for (const res of clients) { try { res.write(data); } catch (e) { clients.delete(res); } } };

const OK_KEY = /^(clinprac360-platform|practiceos-|p360-live-)[\w.:-]{0,120}$/;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.mp4': 'video/mp4', '.pdf': 'application/pdf', '.json': 'application/json', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };
const readBody = (req, max) => new Promise((ok, bad) => { let n = 0; const parts = []; req.on('data', (d) => { n += d.length; if (n > max) { bad(new Error('too large')); req.destroy(); } else parts.push(d); }); req.on('end', () => ok(Buffer.concat(parts).toString('utf8'))); req.on('error', bad); });
const json = (res, code, o, extra) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, extra || {})); res.end(JSON.stringify(o)); };
let bootstrap = null; // when the server starts empty, the first browser may create the demo set-up for 15 minutes

const handler = async (req, res) => {
  const u = new URL(req.url, 'http://x'); const p = decodeURIComponent(u.pathname); const ip = ipOf(req); const client = String(req.headers['x-client'] || u.searchParams.get('c') || '').slice(0, 40);
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Permissions-Policy', 'microphone=(self), camera=(self), geolocation=()');
  const viaHttps = req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
  if (FORCE_HTTPS && !viaHttps) { res.writeHead(301, { Location: 'https://' + req.headers.host + req.url }); return res.end(); }
  if (viaHttps) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    if (p === '/api/health') return json(res, 200, { ok: true, secure: true, clients: clients.size });
    const who = whoOf(req, u); const P = plat(); res.setHeader('X-Auth', who ? who.level : 'none');

    if (p === '/api/login' && req.method === 'POST') { const b = JSON.parse(await readBody(req, 10000) || '{}'); const email = String(b.email || '').trim().toLowerCase();
      if (blocked('ip:' + ip, 30, 15 * 60e3) || blocked('em:' + email, 8, 15 * 60e3)) return json(res, 429, { ok: false, msg: 'Too many sign-in attempts. Wait 15 minutes and try again.' });
      const a = byEmail(P, email); const fail = () => { hit('ip:' + ip, 30, 15 * 60e3); hit('em:' + email, 8, 15 * 60e3); return json(res, 401, { ok: false, msg: 'Email or password is not correct.' }); };
      if (!a) { await pbkdf2(b.password, 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 210000); return fail(); }
      if (a.lockedUntil && a.lockedUntil > Date.now()) return json(res, 423, { ok: false, msg: `Too many attempts. Try again in ${Math.ceil((a.lockedUntil - Date.now()) / 60000)} minute(s).` });
      const h = await pbkdf2(b.password, a.pwSalt, a.iter); if (!timingEq(h, a.pwHash)) return fail();
      if (a.status === 'pending-verify') return json(res, 403, { ok: false, reason: 'verify', msg: 'Please confirm your email address first.' });
      if (a.status !== 'active') return json(res, 403, { ok: false, msg: 'This account is not active. Contact your practice administrator.' });
      const needMfa = !!(a.mfa && a.mfa.enabled); const level = needMfa || b.mfaSetup ? 'mfa' : 'full'; const t = newSession(a.id, level, req);
      return json(res, 200, { ok: true, token: t, level, mfa: needMfa }); }
    if (p === '/api/mfa' && req.method === 'POST') { if (!who) return json(res, 401, { ok: false }); const b = JSON.parse(await readBody(req, 5000) || '{}'); const a = accOf(P, who.acc);
      if (blocked('mfa:' + who.acc, 6, 15 * 60e3)) return json(res, 429, { ok: false, msg: 'Too many wrong codes. Wait 15 minutes.' });
      const code = String(b.code || '').replace(/\s/g, ''); let ok = false;
      if (a && a.mfa && a.mfa.secret && /^\d{6}$/.test(code)) for (const w of [0, -1, 1]) if (totp(a.mfa.secret, Date.now() + w * 30000) === code) ok = true;
      if (!ok && a && a.mfa) { const hsh = sha(code.toUpperCase().replace(/[^A-Z0-9]/g, '')); const i = (a.mfa.recovery || []).indexOf(hsh); if (i >= 0) { const pl = plat(); const acc = accOf(pl, a.id); acc.mfa.recovery.splice(i, 1); kv[PKEY] = JSON.stringify(pl); saveSoon(); notify(PKEY, ''); ok = true; } }
      if (!ok) { hit('mfa:' + who.acc, 6, 15 * 60e3); return json(res, 401, { ok: false }); }
      who.level = 'full'; who.exp = Date.now() + SESSION_MS; saveSessions(); return json(res, 200, { ok: true, level: 'full' }); }
    if (p === '/api/logout' && req.method === 'POST') { if (who) { delete sessions[who.token]; delete seenOf[who.token]; saveSessions(); } return json(res, 200, { ok: true }); }
    if (p === '/api/lookup' && req.method === 'GET') { if (hit('lk:' + ip, 40, 15 * 60e3)) return json(res, 429, { ok: false });
      if (u.searchParams.has('email')) return json(res, 200, { taken: !!byEmail(P, u.searchParams.get('email')) });
      if (u.searchParams.has('invite')) { const code = String(u.searchParams.get('invite') || '').trim().toUpperCase(); const inv = (P && P.invites || []).find((i) => i.code === code && !i.used && i.expires > Date.now());
        if (!inv) return json(res, 404, { ok: false }); cr(client).invites.add(inv.id); const org = (P.orgs || []).find((o) => o.id === inv.orgId); const ds = (P.datasets || []).find((d) => d.id === inv.datasetId);
        return json(res, 200, { ok: true, invite: inv, org: org || null, dataset: ds || null }); }
      return json(res, 400, { ok: false }); }

    // optional AI model step for AI Scribe: only through a provider the practice approved (key set on the server)
    if (p === '/api/ai/scribe' && req.method === 'POST') { if (!who || who.level !== 'full') return json(res, 401, { ok: false });
      const KEY = process.env.SCRIBE_AI_KEY; if (!KEY) return json(res, 501, { ok: false, configured: false, need: 'Set SCRIBE_AI_KEY (and optionally SCRIBE_AI_URL, SCRIBE_AI_MODEL) for a provider covered by a POPIA operator agreement.' });
      if (hit('ai:' + who.acc, 30, 60 * 60e3)) return json(res, 429, { ok: false });
      const b = JSON.parse(await readBody(req, 400000) || '{}'); const prompt = String(b.prompt || '').slice(0, 120000); if (!prompt) return json(res, 400, { ok: false });
      const url = new URL(process.env.SCRIBE_AI_URL || 'https://api.anthropic.com/v1/messages'); const body = JSON.stringify({ model: process.env.SCRIBE_AI_MODEL || 'claude-sonnet-5-5', max_tokens: 4000, messages: [{ role: 'user', content: prompt }] });
      const out = await new Promise((ok) => { const r2 = https.request({ hostname: url.hostname, path: url.pathname, method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01', 'content-length': Buffer.byteLength(body) } }, (rs) => { const parts = []; rs.on('data', (d) => parts.push(d)); rs.on('end', () => ok({ status: rs.statusCode, text: Buffer.concat(parts).toString('utf8') })); });
        r2.on('error', () => ok({ status: 502, text: '' })); r2.setTimeout(60000, () => { r2.destroy(); ok({ status: 504, text: '' }); }); r2.write(body); r2.end(); });
      console.log(`  AI Scribe model call by ${who.acc}: ${out.status}`); // the prompt is never logged
      if (out.status !== 200) return json(res, 502, { ok: false, status: out.status });
      try { const j = JSON.parse(out.text); return json(res, 200, { ok: true, text: (j.content || []).map((x) => x.text || '').join('') }); } catch (e) { return json(res, 502, { ok: false }); } }
    if (p === '/api/kv' && req.method === 'GET') { const out = {};
      Object.keys(kv).forEach((k) => { if (k === PKEY) { const v = view(P, who, client); if (v) { out[k] = JSON.stringify(v); remember(who, client, v); } } else if (canKey(P, who, k)) out[k] = kv[k]; });
      return json(res, 200, out); }
    if (p === '/api/events') { res.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' }); res.write(': connected\n\n'); clients.add(res);
      const t = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { /* ignore */ } }, 25000); req.on('close', () => { clearInterval(t); clients.delete(res); }); return; }
    if (p.startsWith('/api/kv/')) { const k = p.slice(8); if (!OK_KEY.test(k)) { res.writeHead(400); return res.end('bad key'); }
      if (req.method === 'GET') { if (k === PKEY) { const v = view(P, who, client); if (!v) { res.writeHead(404); return res.end(); } remember(who, client, v); res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(JSON.stringify(v)); }
        if (!canKey(P, who, k)) { res.writeHead(who ? 403 : 401); return res.end(); } if (!(k in kv)) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(kv[k]); }
      if (req.method === 'PUT' || req.method === 'POST') {
        const boot = bootstrap && bootstrap.client === client && Date.now() < bootstrap.until;
        if (!P && k === PKEY && !bootstrap) bootstrap = { client, until: Date.now() + 15 * 60e3 };
        const isBoot = boot || (!P && k === PKEY && bootstrap && bootstrap.client === client);
        if (!who && !isBoot && hit('w:' + ip, 60, 60e3)) { res.writeHead(429); return res.end(); }
        const v = await readBody(req, who || isBoot ? MAX_BODY : MAX_ANON_BODY);
        if (k === PKEY) { if (isBoot || !P) { kv[k] = v; saveSoon(); notify(k, client); res.writeHead(204); return res.end(); }
          let inc; try { inc = JSON.parse(v); } catch (e) { res.writeHead(400); return res.end(); }
          const r = mergePlat(P, inc, who, client, seenOf[(who && who.token) || 'c:' + client]); kv[k] = JSON.stringify(r.out); saveSoon(); notify(k, client);
          if (who && who.upgrade) { delete who.upgrade; who.level = 'full'; who.exp = Date.now() + SESSION_MS; saveSessions(); }
          remember(who, client, view(r.out, who, client)); res.writeHead(r.refused ? 207 : 204, { 'X-Refused': String(r.refused) }); return res.end(); }
        if (!(isBoot || canKey(P, who, k))) { res.writeHead(who ? 403 : 401); return res.end(); }
        kv[k] = v; if (!/^p360-live-msg/.test(k)) saveSoon(); notify(k, client); res.writeHead(204); return res.end(); }
      if (req.method === 'DELETE') { if (k === PKEY || !canKey(P, who, k)) { res.writeHead(who ? 403 : 401); return res.end(); } delete kv[k]; saveSoon(); notify(k, client); res.writeHead(204); return res.end(); }
      res.writeHead(405); return res.end(); }
    if (p.startsWith('/api/')) { res.writeHead(404); return res.end(); }

    // static files (the app); never serve data, sessions or server files
    if (/(^|\/)(data|certs|backups|node_modules)(\/|$)|(^|\/)\.|\.(json|pem|sh|bat|md|yaml|yml|txt)$|server\.js$|Dockerfile$/i.test(p) && !/manifest\.json$/.test(p)) { res.writeHead(404); return res.end(); }
    let f = path.normalize(path.join(PUB, p === '/' ? 'index.html' : p)); if (!f.startsWith(PUB)) { res.writeHead(403); return res.end(); }
    if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(PUB, 'index.html');
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' }); fs.createReadStream(f).pipe(res);
  } catch (e) { console.error(e); try { res.writeHead(500); res.end('error'); } catch (x) { /* ignore */ } }
};
const key = path.join(ROOT, 'certs', 'key.pem'), cert = path.join(ROOT, 'certs', 'cert.pem'); const secure = fs.existsSync(key) && fs.existsSync(cert);
const srv = secure ? https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, handler) : http.createServer(handler);
srv.listen(PORT, HOST, () => { const ips = Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address);
  console.log(`\n  Prac360 server is running (${secure ? 'HTTPS' : 'HTTP'}${FORCE_HTTPS ? ', HTTPS enforced' : ''}).\n  Open on this computer:   ${secure ? 'https' : 'http'}://localhost:${PORT}\n${ips.map((ip) => `  Open on the network:     ${secure ? 'https' : 'http'}://${ip}:${PORT}`).join('\n')}\n\n  Data file: ${FILE}\n  Daily backups: ${BDIR}\n  Stop with Ctrl+C.\n`);
  if (!secure && !FORCE_HTTPS) console.log('  Tip: on the internet, use a host that gives HTTPS and set FORCE_HTTPS=1.\n'); });
const stop = () => { if (saveT) { clearTimeout(saveT); writeNow(); } try { fs.writeFileSync(SFILE, JSON.stringify(sessions)); } catch (e) { /* ignore */ } process.exit(0); };
process.on('SIGINT', stop); process.on('SIGTERM', stop);
