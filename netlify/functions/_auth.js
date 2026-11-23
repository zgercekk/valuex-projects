// netlify/functions/_auth.js
// Shared helper: checks that a request comes from a signed-in Netlify Identity user.
// The leading underscore keeps Netlify from deploying this as its own endpoint.
export async function requireUser(req, context) {
  const auth = req.headers.get('authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const token = match[1];
  const identityUrl = (context && context.identity && context.identity.url)
    || `${new URL(req.url).origin}/.netlify/identity`;
  // Hard timeout on the verification call itself. Without this, a slow or
  // unresponsive GoTrue endpoint left requireUser() — and therefore every
  // function that calls it (projects.js, evaluate*.js) — hanging with no
  // upper bound. On the client, loadProjectsFromCloud() re-fires every 30s
  // via setInterval regardless of whether the previous call ever returned,
  // so a hang here didn't just show as a stuck "Checking sync…" — repeated
  // overlapping hung requests against the same origin can exhaust the
  // browser's connection limit for that domain, making the whole site look
  // unreachable, not just this one endpoint. 8s is generously above GoTrue's
  // normal response time but well under Netlify's function execution ceiling.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(`${identityUrl}/user`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error('requireUser: identity verification failed:', err);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export function unauthorized(cors) {
  return new Response(JSON.stringify({ error: 'Unauthorized — sign in required' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}
