// Shared auth helpers: D1 schema, password hashing (PBKDF2), sessions.

export const SESSION_COOKIE = 'ccd_session';
const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000; // Workers' WebCrypto maximum

let schemaReady = false;

export async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    )`),
  ]);
  schemaReady = true;
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, iter, salt, expected] = String(stored).split('$');
  if (scheme !== 'pbkdf2') return false;
  const actual = new Uint8Array(await pbkdf2(password, unb64(salt), Number(iter)));
  const exp = unb64(expected);
  if (actual.length !== exp.length) return false;
  let diff = 0;
  for (let i = 0; i < exp.length; i++) diff |= actual[i] ^ exp[i];
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

export async function createSession(db, userId) {
  const token = b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g, (c) => ({ '+': '-', '/': '_', '=': '' })[c]);
  const expires = Date.now() + SESSION_DAYS * 86400000;
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Date.now()),
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, userId, expires),
  ]);
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

export async function getSessionUser(db, request) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  return db
    .prepare(`SELECT u.id, u.name, u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token = ? AND s.expires_at > ?`)
    .bind(token, Date.now())
    .first();
}

export async function destroySession(db, request) {
  const token = readCookie(request, SESSION_COOKIE);
  if (token) await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

export function validateNewUser({ name, email, password }) {
  if (!name || !String(name).trim()) return 'Name is required';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''))) return 'A valid email is required';
  if (!password || String(password).length < 8) return 'Password must be at least 8 characters';
  return null;
}
