// CFA L1 페이스메이커 서버 (Cloudflare Worker + D1)
// 페이지(index.html)와 로그인·기록 저장 API를 함께 제공합니다.
// 페이지 본문은 GitHub 저장소의 index.html을 읽어와 5분간 캐시해서 보여줍니다.
// 그래서 페이지를 고칠 때는 저장소의 index.html만 바꾸면 되고, 서버를 다시 배포할 필요가 없습니다.
const PAGE_URL = 'https://raw.githubusercontent.com/serendipity-awates/study/main/index.html';
async function html() {
  const r = await fetch(PAGE_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
  if (!r.ok) throw fail(502, '페이지를 불러오지 못했습니다. 잠시 뒤 새로고침하세요');
  return r.text();
}
const MAX_USERS = 5;            // 가입 가능한 계정 수
const SESSION_DAYS = 365;       // 로그인 유지 기간
const MAX_BODY = 1024 * 1024;   // 기록 최대 크기 (1MB)
const LOCK_AFTER = 5, LOCK_MIN = 15;

const enc = new TextEncoder();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async t => hex(await crypto.subtle.digest('SHA-256', enc.encode(t)));
async function pbkdf2(pw, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: 100000 }, key, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '86400',
};
const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS },
});
const fail = (status, error) => json({ error }, status);

async function readJson(req) {
  const len = +(req.headers.get('Content-Length') || 0);
  if (len > MAX_BODY * 2) throw fail(413, '기록이 너무 큽니다');
  const text = await req.text();
  if (text.length > MAX_BODY * 2) throw fail(413, '기록이 너무 큽니다');
  try { return JSON.parse(text || '{}'); } catch { throw fail(400, '잘못된 요청입니다'); }
}

async function newSession(env, userId) {
  const token = rand(32), now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND expires < ?').bind(userId, now),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)').bind(await sha256(token), userId, now + SESSION_DAYS * 864e5),
  ]);
  return token;
}
async function currentUser(req, env) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.get('Authorization') || '');
  if (!m) return null;
  const row = await env.DB.prepare('SELECT s.user_id AS id, u.username, u.recovery_hash IS NOT NULL AS has_recovery, u.google_sub IS NOT NULL AS has_google, u.has_pw, u.email, u.email_verified FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ?')
    .bind(await sha256(m[1]), Date.now()).first();
  return row || null;
}
// 복구 코드: 헷갈리는 글자(0/O, 1/I)를 뺀 32글자로 20자리 = 100비트
const CODE_ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newCode() {
  const b = crypto.getRandomValues(new Uint8Array(20));
  const c = [...b].map(x => CODE_ABC[x & 31]).join('');
  return c.slice(0, 5) + '-' + c.slice(5, 10) + '-' + c.slice(10, 15) + '-' + c.slice(15, 20);
}
const normCode = c => typeof c === 'string' ? c.toUpperCase().replace(/[^A-Z0-9]/g, '') : '';
const codeHash = c => sha256('recovery:' + normCode(c));
async function issueCode(env, userId) {
  const code = newCode();
  await env.DB.prepare('UPDATE users SET recovery_hash = ? WHERE id = ?').bind(await codeHash(code), userId).run();
  return code;
}
// 구글 로그인: 구글이 준 신원 토큰(JWT)을 구글 공개키로 직접 검증합니다.
const b64u = t => Uint8Array.from(atob(t.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((t.length + 3) % 4)), c => c.charCodeAt(0));
async function verifyGoogle(cred, clientId) {
  const parts = typeof cred === 'string' ? cred.split('.') : [];
  if (parts.length !== 3) return null;
  const header = JSON.parse(new TextDecoder().decode(b64u(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(b64u(parts[1])));
  if (header.alg !== 'RS256') return null;
  const certs = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = (certs.keys || []).find(k => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  if (!ok) return null;
  if (payload.aud !== clientId) return null;
  if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') return null;
  if (!(payload.exp * 1000 > Date.now())) return null;
  if (!payload.sub || payload.email_verified !== true) return null;
  return { sub: String(payload.sub), email: String(payload.email || '') };
}
async function googleLogin(req, env) {
  if (!env.GOOGLE_CLIENT_ID) return fail(503, '구글 로그인이 아직 준비되지 않았습니다');
  const { credential } = await readJson(req);
  const g = await verifyGoogle(credential, env.GOOGLE_CLIENT_ID);
  if (!g) return fail(401, '구글 로그인 확인에 실패했습니다. 다시 해보세요');
  const me = await currentUser(req, env);
  const owner = await env.DB.prepare('SELECT * FROM users WHERE google_sub = ?').bind(g.sub).first();
  if (me) {
    if (owner && owner.id !== me.id) return fail(409, '이 구글 계정은 이미 다른 아이디에 연결돼 있습니다');
    await env.DB.prepare('UPDATE users SET google_sub = ?, email = ? WHERE id = ?').bind(g.sub, g.email, me.id).run();
    return json({ token: (req.headers.get('Authorization') || '').slice(7), username: me.username, google: true, linked: true, hasPassword: !!me.has_pw });
  }
  if (owner) {
    await env.DB.prepare('UPDATE users SET email = ? WHERE id = ?').bind(g.email, owner.id).run();
    return json({ token: await newSession(env, owner.id), username: owner.username, google: true, hasPassword: !!owner.has_pw });
  }
  const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  if (n >= MAX_USERS) return fail(403, '이 서버는 가입 인원이 가득 찼습니다');
  let base = (g.email.split('@')[0] || 'user').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 24);
  if (base.length < 3) base = 'user' + base;
  let name = base;
  for (let i = 2; await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(name).first(); i++) name = base + i;
  const salt = rand(16), hash = await pbkdf2(rand(24), salt);
  const r = await env.DB.prepare('INSERT INTO users (username, salt, hash, created, google_sub, email, has_pw) VALUES (?, ?, ?, ?, ?, ?, 0)').bind(name, salt, hash, Date.now(), g.sub, g.email).run();
  return json({ token: await newSession(env, r.meta.last_row_id), username: name, google: true, created: true, hasPassword: false });
}
const isEmail = e => typeof e === 'string' && e.length <= 100 && /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e);
const validName = u => typeof u === 'string' && (/^[A-Za-z0-9_.-]{3,30}$/.test(u) || isEmail(u));

// 이메일 인증번호: Resend로 6자리 번호를 보냅니다. 번호는 해시만 저장하고 10분 뒤 만료, 5번 틀리면 무효.
const CODE_MIN = 10, CODE_TRIES = 5;
const sixDigits = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
async function sendMail(env, to, subject, code, what) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'CFA 페이스메이커 <onboarding@resend.dev>', to: [to], subject,
      text: what + '\n\n인증번호: ' + code + '\n\n' + CODE_MIN + '분 안에 입력해 주세요. 직접 요청하지 않았다면 이 메일은 무시하세요.',
      html: '<div style="font-family:sans-serif;font-size:15px;line-height:1.6"><p>' + what + '</p><p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:16px 0">' + code + '</p><p style="color:#666">' + CODE_MIN + '분 안에 입력해 주세요. 직접 요청하지 않았다면 이 메일은 무시하세요.</p></div>',
    }),
  });
  if (r.ok) return null;
  let msg = ''; try { msg = (await r.json()).message || ''; } catch {}
  if (r.status === 403 || /own email|testing emails|verify a domain/i.test(msg)) return '이 주소로는 메일을 보낼 수 없습니다. Resend에 가입한 이메일 주소를 넣어주세요';
  return '메일을 보내지 못했습니다. 잠시 뒤 다시 해보세요';
}
async function makeCode(env, userId, purpose, email) {
  const now = Date.now();
  const last = await env.DB.prepare('SELECT created FROM codes WHERE user_id = ? AND purpose = ? ORDER BY created DESC LIMIT 1').bind(userId, purpose).first();
  if (last && now - last.created < 60000) return { wait: Math.ceil((60000 - (now - last.created)) / 1000) };
  const code = sixDigits();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM codes WHERE user_id = ? AND purpose = ?').bind(userId, purpose),
    env.DB.prepare('INSERT INTO codes (user_id, purpose, code_hash, email, expires, tries, created) VALUES (?, ?, ?, ?, ?, 0, ?)').bind(userId, purpose, await sha256('code:' + userId + ':' + code), email, now + CODE_MIN * 60000, now),
  ]);
  return { code };
}
async function checkCode(env, userId, purpose, code) {
  const row = await env.DB.prepare('SELECT * FROM codes WHERE user_id = ? AND purpose = ?').bind(userId, purpose).first();
  if (!row || row.expires < Date.now() || row.tries >= CODE_TRIES) return { err: '인증번호가 만료됐습니다. 새로 받아주세요' };
  const ok = typeof code === 'string' && same(await sha256('code:' + userId + ':' + code.replace(/[^0-9]/g, '')), row.code_hash);
  if (!ok) {
    await env.DB.prepare('UPDATE codes SET tries = tries + 1 WHERE id = ?').bind(row.id).run();
    const left = CODE_TRIES - row.tries - 1;
    return { err: left > 0 ? '인증번호가 맞지 않습니다 (' + left + '번 남음)' : '인증번호를 여러 번 틀렸습니다. 새로 받아주세요' };
  }
  await env.DB.prepare('DELETE FROM codes WHERE id = ?').bind(row.id).run();
  return { email: row.email };
}
// 로그인한 상태에서 내 이메일 등록 (인증번호 발송 → 확인)
async function emailStart(req, env, me) {
  if (!env.RESEND_API_KEY) return fail(503, '이메일 기능이 아직 준비되지 않았습니다');
  const { email } = await readJson(req);
  if (!isEmail(email)) return fail(400, '이메일 주소를 확인해 주세요');
  const addr = email.trim().toLowerCase();
  const taken = await env.DB.prepare('SELECT id FROM users WHERE (email = ? AND email_verified = 1) OR username = ?').bind(addr, addr).first();
  if (taken && taken.id !== me.id) return fail(409, '이 이메일은 다른 계정에서 쓰고 있습니다');
  const c = await makeCode(env, me.id, 'verify', addr);
  if (c.wait) return fail(429, c.wait + '초 뒤에 다시 받을 수 있습니다');
  const err = await sendMail(env, addr, '[CFA 페이스메이커] 이메일 인증번호 ' + c.code, '이메일을 등록하려면 아래 인증번호를 입력하세요.');
  if (err) { await env.DB.prepare('DELETE FROM codes WHERE user_id = ? AND purpose = ?').bind(me.id, 'verify').run(); return fail(502, err); }
  return json({ ok: true, sentTo: addr });
}
async function emailConfirm(req, env, me) {
  const { code, useAsId } = await readJson(req);
  const r = await checkCode(env, me.id, 'verify', code);
  if (r.err) return fail(400, r.err);
  const taken = useAsId ? await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(r.email).first() : null;
  if (taken && taken.id !== me.id) return fail(409, '이 이메일은 다른 계정의 아이디입니다');
  await env.DB.prepare('UPDATE users SET email = ?, email_verified = 1' + (useAsId ? ', username = ?' : '') + ' WHERE id = ?')
    .bind(...(useAsId ? [r.email, r.email, me.id] : [r.email, me.id])).run();
  return json({ ok: true, email: r.email, username: useAsId ? r.email : me.username });
}
// 로그인 없이: 이메일로 인증번호 받아 아이디 확인 + 새 비밀번호
async function forgotStart(req, env) {
  if (!env.RESEND_API_KEY) return fail(503, '이메일 기능이 아직 준비되지 않았습니다');
  const { email } = await readJson(req);
  if (!isEmail(email)) return fail(400, '이메일 주소를 확인해 주세요');
  const addr = email.trim().toLowerCase();
  const u = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND email_verified = 1').bind(addr).first();
  if (!u) return fail(404, '이 이메일로 등록된 계정이 없습니다. 로그인 후 내 계정에서 이메일을 먼저 등록해야 합니다');
  const c = await makeCode(env, u.id, 'reset', addr);
  if (c.wait) return fail(429, c.wait + '초 뒤에 다시 받을 수 있습니다');
  const err = await sendMail(env, addr, '[CFA 페이스메이커] 비밀번호 재설정 인증번호 ' + c.code, '아이디 확인과 비밀번호 재설정을 위한 인증번호입니다.');
  if (err) { await env.DB.prepare('DELETE FROM codes WHERE user_id = ? AND purpose = ?').bind(u.id, 'reset').run(); return fail(502, err); }
  return json({ ok: true });
}
async function forgotConfirm(req, env) {
  const { email, code, password } = await readJson(req);
  if (!isEmail(email)) return fail(400, '이메일 주소를 확인해 주세요');
  if (!validPw(password)) return fail(400, '새 비밀번호는 8자 이상으로 정해주세요');
  const u = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND email_verified = 1').bind(email.trim().toLowerCase()).first();
  if (!u) return fail(400, '인증번호가 만료됐습니다. 새로 받아주세요');
  const r = await checkCode(env, u.id, 'reset', code);
  if (r.err) return fail(400, r.err);
  const salt = rand(16), hash = await pbkdf2(password, salt);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET salt = ?, hash = ?, fails = 0, locked_until = 0, has_pw = 1 WHERE id = ?').bind(salt, hash, u.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id),
  ]);
  return json({ token: await newSession(env, u.id), username: u.username, emailVerified: true, email: u.email });
}
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 200;

async function signup(req, env) {
  const { username, password } = await readJson(req);
  if (!validName(username)) return fail(400, '아이디는 이메일 주소 또는 영문·숫자 3~30자로 정해주세요');
  if (!validPw(password)) return fail(400, '비밀번호는 8자 이상으로 정해주세요');
  const name = username.toLowerCase();
  const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  if (n >= MAX_USERS) return fail(403, '이 서버는 가입 인원이 가득 찼습니다');
  if (await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(name).first()) return fail(409, '이미 있는 아이디입니다. 로그인하거나 다른 아이디를 쓰세요');
  const salt = rand(16), hash = await pbkdf2(password, salt);
  const r = await env.DB.prepare('INSERT INTO users (username, salt, hash, created) VALUES (?, ?, ?, ?)').bind(name, salt, hash, Date.now()).run();
  const id = r.meta.last_row_id;
  return json({ token: await newSession(env, id), username: name, recoveryCode: await issueCode(env, id) });
}

async function login(req, env) {
  const { username, password } = await readJson(req);
  const bad = () => fail(401, '아이디 또는 비밀번호가 맞지 않습니다');
  if (!validName(username) || typeof password !== 'string') return bad();
  const name = username.toLowerCase(), now = Date.now();
  const u = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(name).first();
  if (!u) { await pbkdf2(password, '00'.repeat(16)); return bad(); }
  if (u.locked_until > now) return fail(429, '비밀번호를 여러 번 틀려서 잠겼습니다. ' + Math.ceil((u.locked_until - now) / 60000) + '분 뒤에 다시 해보세요');
  if (!same(await pbkdf2(password, u.salt), u.hash)) {
    const fails = u.fails + 1;
    if (fails >= LOCK_AFTER) await env.DB.prepare('UPDATE users SET fails = 0, locked_until = ? WHERE id = ?').bind(now + LOCK_MIN * 60000, u.id).run();
    else await env.DB.prepare('UPDATE users SET fails = ? WHERE id = ?').bind(fails, u.id).run();
    return bad();
  }
  if (u.fails) await env.DB.prepare('UPDATE users SET fails = 0 WHERE id = ?').bind(u.id).run();
  return json({ token: await newSession(env, u.id), username: u.username, hasRecovery: !!u.recovery_hash, google: !!u.google_sub, hasPassword: true, email: u.email_verified ? u.email : null });
}

// 아이디·비밀번호 찾기: 복구 코드(아이디는 선택)로 계정을 찾아 새 비밀번호를 정합니다. 쓴 복구 코드는 버리고 새 코드를 줍니다.
async function resetPassword(req, env) {
  const { username, code, password } = await readJson(req);
  const bad = () => fail(401, '복구 코드가 맞지 않습니다. 대시(-) 없이 넣어도 됩니다');
  if (normCode(code).length !== 20) return bad();
  if (username && !validName(username)) return bad();
  if (!validPw(password)) return fail(400, '새 비밀번호는 8자 이상으로 정해주세요');
  const now = Date.now();
  // 아이디를 몰라도 복구 코드만으로 계정을 찾습니다 (코드는 계정마다 다르고 100비트라 추측할 수 없습니다)
  const u = username
    ? await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username.toLowerCase()).first()
    : await env.DB.prepare('SELECT * FROM users WHERE recovery_hash = ?').bind(await codeHash(code)).first();
  if (!u) return bad();
  if (u.locked_until > now) return fail(429, '여러 번 틀려서 잠겼습니다. ' + Math.ceil((u.locked_until - now) / 60000) + '분 뒤에 다시 해보세요');
  if (!u.recovery_hash || !same(await codeHash(code), u.recovery_hash)) {
    const fails = u.fails + 1;
    if (fails >= LOCK_AFTER) await env.DB.prepare('UPDATE users SET fails = 0, locked_until = ? WHERE id = ?').bind(now + LOCK_MIN * 60000, u.id).run();
    else await env.DB.prepare('UPDATE users SET fails = ? WHERE id = ?').bind(fails, u.id).run();
    return bad();
  }
  const salt = rand(16), hash = await pbkdf2(password, salt);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET salt = ?, hash = ?, fails = 0, locked_until = 0, has_pw = 1 WHERE id = ?').bind(salt, hash, u.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id),
  ]);
  return json({ token: await newSession(env, u.id), username: u.username, recoveryCode: await issueCode(env, u.id) });
}

async function changePassword(req, env, me) {
  const { old, password } = await readJson(req);
  if (!validPw(password)) return fail(400, '새 비밀번호는 8자 이상으로 정해주세요');
  const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(me.id).first();
  if (u.has_pw && (typeof old !== 'string' || !same(await pbkdf2(old, u.salt), u.hash))) return fail(403, '현재 비밀번호가 맞지 않습니다');
  const salt = rand(16), hash = await pbkdf2(password, salt);
  const tokenHash = await sha256((req.headers.get('Authorization') || '').slice(7));
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET salt = ?, hash = ?, has_pw = 1 WHERE id = ?').bind(salt, hash, me.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(me.id, tokenHash),
  ]);
  return json({ ok: true });
}

async function getData(env, me) {
  const row = await env.DB.prepare('SELECT body, updated_at FROM data WHERE user_id = ?').bind(me.id).first();
  return json(row ? { body: JSON.parse(row.body), updatedAt: row.updated_at } : { body: null, updatedAt: 0 });
}

async function putData(req, env, me) {
  const { body, updatedAt } = await readJson(req);
  if (!body || typeof body !== 'object' || !Number.isFinite(updatedAt)) return fail(400, '잘못된 기록 형식입니다');
  const text = JSON.stringify(body);
  if (text.length > MAX_BODY) return fail(413, '기록이 너무 큽니다');
  const cur = await env.DB.prepare('SELECT body, updated_at FROM data WHERE user_id = ?').bind(me.id).first();
  if (cur && cur.updated_at > updatedAt) return json({ error: '더 최신 기록이 서버에 있습니다', body: JSON.parse(cur.body), updatedAt: cur.updated_at }, 409);
  await env.DB.prepare('INSERT INTO data (user_id, body, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at')
    .bind(me.id, text, updatedAt).run();
  return json({ ok: true, updatedAt });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      if (!url.pathname.startsWith('/api/')) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return fail(405, '허용되지 않는 요청입니다');
        if (url.pathname !== '/' && url.pathname !== '/index.html') return Response.redirect(url.origin + '/', 302);
        return new Response(await html(), { headers: {
          'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache',
          'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
        } });
      }
      const route = req.method + ' ' + url.pathname;
      if (route === 'POST /api/signup') return await signup(req, env);
      if (route === 'POST /api/login') return await login(req, env);
      if (route === 'POST /api/reset') return await resetPassword(req, env);
      if (route === 'POST /api/google') return await googleLogin(req, env);
      if (route === 'GET /api/config') return json({ googleClientId: env.GOOGLE_CLIENT_ID || null, email: !!env.RESEND_API_KEY });
      if (route === 'POST /api/forgot') return await forgotStart(req, env);
      if (route === 'POST /api/forgot/confirm') return await forgotConfirm(req, env);
      const me = await currentUser(req, env);
      if (!me) return fail(401, '로그인이 필요합니다');
      if (route === 'GET /api/data') return await getData(env, me);
      if (route === 'PUT /api/data') return await putData(req, env, me);
      if (route === 'POST /api/password') return await changePassword(req, env, me);
      if (route === 'GET /api/me') return json({ username: me.username, hasRecovery: !!me.has_recovery, google: !!me.has_google, hasPassword: !!me.has_pw, email: me.email_verified ? me.email : null });
      if (route === 'POST /api/email') return await emailStart(req, env, me);
      if (route === 'POST /api/email/confirm') return await emailConfirm(req, env, me);
      if (route === 'POST /api/recovery-code') return json({ recoveryCode: await issueCode(env, me.id) });
      if (route === 'POST /api/logout') {
        await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256((req.headers.get('Authorization') || '').slice(7))).run();
        return json({ ok: true });
      }
      return fail(404, '없는 주소입니다');
    } catch (e) {
      if (e instanceof Response) return e;
      return fail(500, '서버 오류가 발생했습니다. 잠시 뒤 다시 해보세요');
    }
  },
};
