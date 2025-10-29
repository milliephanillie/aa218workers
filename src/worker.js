import { TecBaseApi } from './TecBaseApi.js';
import { TecCookie } from './TecCookie.js';

const SESSION = new TecCookie({
  name: 'aa218_ok',
  maxAge: 60 * 60 * 24 * 30,
  path: '/',
  secure: true,
  httpOnly: true,
  sameSite: 'Lax'
});

const ALLOWED_ORIGINS = ['https://aa218.club', 'https://www.aa218.club'];

function cors(origin) {
  const o = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}

function hasCookie(request, cookieName = 'aa218_ok') {
  const c = request.headers.get('Cookie') || '';
  return c.split(/;\s*/).some(p => p.startsWith(cookieName + '='));
}

function stripParam(u, key) {
  const url = new URL(u);
  url.searchParams.delete(key);
  return url.toString();
}

function buildArgs(request, url) {
  return {
    clientRequestDateTime: new Date().toISOString(),
    visitorRemoteAddr: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '',
    visitorUserAgent: request.headers.get('User-Agent') || '',
    visitorQueryString: url.search.slice(1),
    visitorRequestAsset: url.pathname,
    visitorAccept: request.headers.get('Accept') || '',
    visitorAcceptEncoding: request.headers.get('Accept-Encoding') || '',
    visitorAcceptLanguage: request.headers.get('Accept-Language') || '',
    visitorReqMethod: request.method,
    visitorReferer: request.headers.get('Referer') || '',
    clientVar1: url.searchParams.get('cv1') || '',
    clientVar2: url.searchParams.get('cv2') || '',
    clientVar3: url.searchParams.get('cv3') || '',
    clientVar4: url.searchParams.get('cv4') || '',
    clientVar5: url.searchParams.get('cv5') || '',
    clientVar6: url.searchParams.get('cv6') || '',
    platform: 'worker',
    major_version: '1',
    minor_version: '0'
  };
}

// Treat any 2xx from Azure as PASS. If your function returns a JSON {ok:true/false},
// you can tighten this to check that explicitly.
function isPass(resp) {
  if (!resp) return false;
  if (typeof resp.status === 'number') return resp.status >= 200 && resp.status < 300;
  if (resp.ok === false) return false;
  return true;
}

// Robust request body parser: JSON and form-encoded supported.
async function parseBody(request) {
  const ctype = (request.headers.get('content-type') || '').toLowerCase();
  const raw = await request.text();

  if (!raw || !raw.trim()) return {};

  // JSON path
  if (ctype.includes('application/json')) {
    try { return JSON.parse(raw); } catch { return {}; }
  }

  // x-www-form-urlencoded path
  if (ctype.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(raw);
    const out = {};
    for (const [k, v] of params.entries()) out[k] = v;
    return out;
  }

  // Last-ditch: try JSON anyway
  try { return JSON.parse(raw); } catch { return {}; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const azure = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    // CORS preflight for /api/*
    if (url.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...cors(origin), 'Cache-Control': 'no-store' }
      });
    }

    // ---------------------------
    // TEST OVERRIDES (exact spec)
    // ---------------------------
    const authParam = url.searchParams.get('auth');
    if (authParam === 'test-true') {
      // Set cookie and strip param; do NOT redirect to password
      const headers = new Headers({ 'Cache-Control': 'no-store', ...cors(origin) });
      headers.set('Set-Cookie', SESSION.set('1'));
      headers.set('Location', stripParam(url.toString(), 'auth'));
      return new Response(null, { status: 302, headers });
    }
    if (authParam === 'test-false') {
      // Clear cookie and force redirect to password
      const headers = new Headers({ 'Cache-Control': 'no-store', ...cors(origin) });
      headers.set('Set-Cookie', SESSION.clear());
      headers.set('Location', `${url.origin}/password.html`);
      return new Response(null, { status: 302, headers });
    }

    // ---------------------------
    // API: LOGIN (Azure decides)
    // ---------------------------
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const headers = new Headers({
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...cors(origin)
      });

      try {
        const body = await parseBody(request);
        const submittedPassword = (body.password || '').toString().trim();

        if (!submittedPassword) {
          return new Response(JSON.stringify({ ok: false, message: 'Password is required' }), { status: 400, headers });
        }

        const args = buildArgs(request, url);
        args.submittedPassword = submittedPassword;

        const resp = await azure.get('pingfn', { queryString: args });

        if (!isPass(resp)) {
          return new Response(JSON.stringify({ ok: false, message: 'Invalid password' }), { status: 401, headers });
        }

        headers.set('Set-Cookie', SESSION.set('1'));
        return new Response(JSON.stringify({ ok: true, ts: new Date().toISOString() }), { status: 200, headers });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, message: 'Invalid request format' }), { status: 400, headers });
      }
    }

    // ---------------------------
    // API: LOGOUT (clear cookie)
    // ---------------------------
    if (url.pathname === '/api/logout') {
      const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      headers.set('Set-Cookie', SESSION.clear());
      return new Response(null, { status: 204, headers });
    }

    // ---------------------------
    // API: Proxy to Azure
    // ---------------------------
    if (url.pathname.startsWith('/api/')) {
      const path = url.pathname.replace(/^\/api\//, '');
      let proxied;
      if (request.method === 'GET') {
        proxied = await azure.get(path, { queryString: url.search.slice(1) });
      } else if (request.method === 'POST') {
        const buf = await request.arrayBuffer();
        proxied = await azure.post(path, {
          queryString: url.search.slice(1),
          body: buf,
          headers: { 'content-type': request.headers.get('content-type') || 'application/json' }
        });
      } else {
        return new Response('Method Not Allowed', { status: 405, headers: { ...cors(origin) } });
      }

      const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      const ct = proxied.headers?.get?.('content-type');
      if (ct) headers.set('Content-Type', ct);
      const data = proxied.data ?? proxied.raw ?? '';
      return new Response(typeof data === 'string' ? data : JSON.stringify(data), {
        status: proxied.status || (proxied.ok ? 200 : 502),
        headers
      });
    }

    // Public password page always passes
    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    // If session cookie is present → allow
    if (hasCookie(request)) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    // No cookie → ask Azure gate
    const gateArgs = buildArgs(request, url);
    const gateResp = await azure.get('pingfn', { queryString: gateArgs });
    if (isPass(gateResp)) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    // Default: redirect to password
    return new Response(null, {
      status: 302,
      headers: { 'Location': `${url.origin}/password.html`, 'Cache-Control': 'no-store' }
    });
  }
};
