// Google sign-in (redirect mode) lands here with the ID token.
// We check Google's CSRF token, then hand the token to the app in the URL fragment
// (fragments never reach any server). The app finishes sign-in with Supabase.
export async function onRequestPost({ request }) {
  const form = await request.formData();
  const credential = form.get('credential') || '';
  const csrfBody = form.get('g_csrf_token') || '';
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)g_csrf_token=([^;]+)/);
  const csrfCookie = m ? decodeURIComponent(m[1]) : '';
  const origin = new URL(request.url).origin;
  if (!credential || !csrfBody || csrfBody !== csrfCookie) {
    return Response.redirect(`${origin}/#gsi_error=1`, 303);
  }
  return new Response(null, {
    status: 303,
    headers: { Location: `${origin}/#gsi=${encodeURIComponent(credential)}`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' },
  });
}
export function onRequestGet({ request }) {
  return Response.redirect(new URL('/', request.url).toString(), 303);
}
