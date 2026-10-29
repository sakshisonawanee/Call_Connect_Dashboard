import { createSession, json, verifyPassword } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json().catch(() => ({}));
  if (!email || !password) return json({ error: 'Email and password are required' }, 400);

  const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE email = ?').bind(String(email).trim()).first();
  if (!user || !(await verifyPassword(String(password), user.password_hash))) {
    return json({ error: 'Wrong email or password' }, 401);
  }
  return json({ ok: true }, 200, { 'Set-Cookie': await createSession(env.DB, user.id) });
}
