// Admin-only (enforced in _middleware.js): list and add users.
import { hashPassword, json, validateNewUser } from '../../_lib/auth.js';

export async function onRequestGet({ env, data }) {
  const { results } = await env.DB.prepare('SELECT id, name, email, role, created_at FROM users ORDER BY created_at').all();
  return json({ users: results, me: data.user.id });
}

export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => ({}));
  const problem = validateNewUser(body);
  if (problem) return json({ error: problem }, 400);
  const role = body.role === 'admin' ? 'admin' : 'user';

  try {
    await env.DB.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)')
      .bind(body.name.trim(), body.email.trim(), await hashPassword(body.password), role)
      .run();
  } catch (e) {
    if (String(e).includes('UNIQUE')) return json({ error: 'A user with that email already exists' }, 409);
    throw e;
  }
  return json({ ok: true }, 201);
}
