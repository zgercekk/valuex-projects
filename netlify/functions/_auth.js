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
  // 8s timeout so a slow identity check can never hang the function.
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
