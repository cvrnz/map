/*
 * Single sign-on for the cvrnz apps: Vercel Routing Middleware.
 *
 * Source: hub/sso/middleware.ts. Every app has a copy at middleware.ts (in the project root,
 * next to package.json) with its own APP; edit it here and copy it to each app
 * (hub/sso/readme.md lists them).
 *
 * Runs before Vercel serves anything, so an app's pages and files only reach users whose
 * Supabase token (in the shared .cvrnz.com session cookie) is genuine, current and lists this
 * app in its `app_access` claim. Pages without that go to hub to sign in (which also refreshes
 * an expired token and comes straight back) or to hear that they have no access. Other requests
 * get a 401 or 403.
 */
import {next} from '@vercel/functions';
import {createRemoteJWKSet, jwtVerify} from 'jose';

const APP = 'map';

const SUPABASE_URL = 'https://qlqqjsamclodxgrpcnxz.supabase.co';
const HUB_URL = 'https://www.cvrnz.com';
const COOKIE = 'sb-qlqqjsamclodxgrpcnxz-auth-token';

// Pages need a current token. Files (scripts, styles, images) also take one that expired within
// this window, so a tab left open can still load a lazily loaded chunk; the app refreshes the
// token itself as soon as it runs.
const FILE_GRACE_SECONDS = 24 * 60 * 60;

const keys = createRemoteJWKSet(new URL(`${SUPABASE_URL}/auth/v1/.well-known/jwks.json`));

export const config = {matcher: '/:path*'};

export default async function middleware(request: Request): Promise<Response> {
  const isPage =
    request.headers.get('sec-fetch-dest') === 'document' || (request.headers.get('accept') ?? '').includes('text/html');

  const token = accessToken(request.headers.get('cookie') ?? '');
  if (token) {
    try {
      const {payload} = await jwtVerify(token, keys, {
        issuer: `${SUPABASE_URL}/auth/v1`,
        audience: 'authenticated',
        clockTolerance: isPage ? 0 : FILE_GRACE_SECONDS,
      });
      const apps = payload.app_access;
      if (Array.isArray(apps) && apps.includes(APP)) return next();
      if (isPage) return Response.redirect(`${HUB_URL}/?denied=${APP}`, 302);
      return new Response('Forbidden', {status: 403});
    } catch {
      // Expired, forged or unreadable: sign in again.
    }
  }

  if (!isPage) return new Response('Unauthorized', {status: 401});
  const signIn = new URL('/sign-in', HUB_URL);
  signIn.searchParams.set('next', request.url);
  return Response.redirect(signIn.href, 302);
}

/**
 * The access token from @supabase/ssr's session cookie. The cookie holds the session as JSON,
 * base64url encoded behind a `base64-` prefix, and is split into `.0`, `.1`… chunks when long.
 */
function accessToken(header: string): string | null {
  const cookies = new Map<string, string>();
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0) cookies.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }

  let raw = cookies.get(COOKIE);
  if (raw === undefined) {
    const chunks: string[] = [];
    for (let i = 0; cookies.has(`${COOKIE}.${i}`); i++) chunks.push(cookies.get(`${COOKIE}.${i}`) ?? '');
    if (chunks.length === 0) return null;
    raw = chunks.join('');
  }

  try {
    raw = decodeURIComponent(raw);
    const json = raw.startsWith('base64-') ? fromBase64Url(raw.slice('base64-'.length)) : raw;
    const session = JSON.parse(json) as {access_token?: unknown};
    return typeof session.access_token === 'string' ? session.access_token : null;
  } catch {
    return null;
  }
}

function fromBase64Url(value: string): string {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '='));
  return new TextDecoder().decode(Uint8Array.from(binary, c => c.charCodeAt(0)));
}
