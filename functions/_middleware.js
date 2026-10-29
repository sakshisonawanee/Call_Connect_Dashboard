// Gatekeeper for every request: only signed-in users see the dashboard.
import { ensureSchema, getSessionUser, json } from './_lib/auth.js';

const PUBLIC_PATHS = new Set(['/login', '/login.html', '/api/login', '/setup', '/setup.html', '/api/setup']);
const ADMIN_PATHS = ['/admin', '/admin.html', '/api/users'];

export async function onRequest({ request, env, next, data }) {
  if (!env.DB) return new Response('Database binding "DB" is not configured.', { status: 500 });
  await ensureSchema(env.DB);

  const url = new URL(request.url);
  if (PUBLIC_PATHS.has(url.pathname)) return next();

  const user = await getSessionUser(env.DB, request);
  if (!user) {
    if (url.pathname.startsWith('/api/')) return json({ error: 'Not signed in' }, 401);
    return Response.redirect(new URL('/login', url).toString(), 302);
  }

  const isAdminPath = ADMIN_PATHS.some((p) => url.pathname === p || url.pathname.startsWith(p + '/'));
  if (isAdminPath && user.role !== 'admin') {
    return url.pathname.startsWith('/api/') ? json({ error: 'Admins only' }, 403) : new Response('Admins only', { status: 403 });
  }

  data.user = user;
  const response = await next();

  // Add a small "signed in as / logout" bar to the dashboard page.
  if (!isAdminPath && (response.headers.get('Content-Type') || '').includes('text/html')) {
    return new HTMLRewriter().on('body', new UserBar(user)).transform(response);
  }
  return response;
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

class UserBar {
  constructor(user) { this.user = user; }
  element(body) {
    const adminLink = this.user.role === 'admin' ? '<a href="/admin" style="color:inherit">Manage users</a> · ' : '';
    body.append(
      `<div style="position:fixed;top:8px;right:8px;z-index:9999;font:12px system-ui,sans-serif;background:rgba(127,127,127,.15);backdrop-filter:blur(6px);padding:6px 10px;border-radius:8px">
        ${esc(this.user.name)} · ${adminLink}<form method="post" action="/api/logout" style="display:inline;margin:0"><button style="font:inherit;background:none;border:0;padding:0;color:inherit;text-decoration:underline;cursor:pointer">Log out</button></form>
      </div>`,
      { html: true },
    );
  }
}
