// One-time creation of the first admin. Disabled as soon as any user exists.
import { createSession, hashPassword, json, validateNewUser } from '../_lib/auth.js';

async function userCount(db) {
  return (await db.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
}

export async function onRequestGet({ env }) {
  return json({ setupOpen: (await userCount(env.DB)) === 0 });
}

export async function onRequestPost({ request, env }) {
  if ((await userCount(env.DB)) > 0) return json({ error: 'Setup is already done. Ask an admin for an account.' }, 403);

  const body = await request.json().catch(() => ({}));
  const problem = validateNewUser(body);
  if (problem) return json({ error: problem }, 400);

  const result = await env.DB.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .bind(body.name.trim(), body.email.trim(), await hashPassword(body.password), 'admin')
    .run();
  return json({ ok: true }, 200, { 'Set-Cookie': await createSession(env.DB, result.meta.last_row_id) });
}
