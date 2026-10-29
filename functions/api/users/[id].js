// Admin-only (enforced in _middleware.js): reset a password or remove a user.
import { hashPassword, json } from '../../_lib/auth.js';

export async function onRequestPatch({ request, params, env }) {
  const { password } = await request.json().catch(() => ({}));
  if (!password || String(password).length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(await hashPassword(password), params.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id),
  ]);
  return json({ ok: true });
}

export async function onRequestDelete({ params, env, data }) {
  if (String(params.id) === String(data.user.id)) return json({ error: "You can't delete your own account" }, 400);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id),
    env.DB.prepare('DELETE FROM users WHERE id = ?').bind(params.id),
  ]);
  return json({ ok: true });
}
