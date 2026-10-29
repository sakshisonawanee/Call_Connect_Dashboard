import { destroySession } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const cookie = await destroySession(env.DB, request);
  return new Response(null, { status: 303, headers: { Location: '/login', 'Set-Cookie': cookie } });
}
