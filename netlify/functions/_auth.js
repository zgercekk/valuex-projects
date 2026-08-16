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
  try {
    const res = await fetch(`${identityUrl}/user`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error('requireUser: identity verification failed:', err);
    return null;
  }
}

export function unauthorized(cors) {
  return new Response(JSON.stringify({ error: 'Unauthorized — sign in required' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}
