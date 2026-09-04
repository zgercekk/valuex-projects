// netlify/functions/_auth.js
//
// Shared helper for gating internal-only endpoints behind a signed-in
// Netlify Identity user. The leading underscore is Netlify's convention for
// excluding a file from the functions bundle, so this is never itself
// deployed as a callable endpoint.
//
// V1 (classic event/context) functions get a pre-decoded
// context.clientContext.user for free. The V2 functions used throughout
// this project (`export default async (req, context) => {}`) don't get
// that, so the token is verified here the same way the Identity widget
// itself does: forward it to GoTrue's own /user endpoint. A 200 back means
// the token is live; anything else means it's missing, expired, or forged.
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
