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

function hasCookie(request) {
  const c = request.headers.get('Cookie') || '';
  return c.split(/;\s*/).some(p => p.startsWith('aa218_ok='));
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

function isPass(res) {
  if (!res) return false;
  if (res.ok === false) return false;
  if (typeof res.status === 'number' && (res.status < 200 || res.status >= 300)) return false;
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const azure = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    // CORS preflight for any /api/* endpoint
    if (url.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...cors(origin), 'Cache-Control': 'no-store' } });
    }

    // Explicit login via POST -> Azure validates; on success set cookie
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const h = new Headers({ 'Content-Type': 'application/json', ...cors(origin), 'Cache-Control': 'no-store' });
      try {
        const body = await request.json();
        const pw = String(body?.password || '').trim();
        if (!pw) return new Response(JSON.stringify({ ok: false, message: 'Password is required' }), { status: 400, headers: h });

        const args = buildArgs(request, url);
        args.submittedPassword = pw;

        const resp = await azure.get('pingfn', { queryString: args });
        if (!isPass(resp)) {
          return new Response(JSON.stringify({ ok: false, message: 'Invalid password' }), { status: 401, headers: h });
        }

        h.set('Set-Cookie', SESSION.set('1'));
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
      } catch {
        return new Response(JSON.stringify({ ok: false, message: 'Invalid request format' }), { status: 400, headers: h });
      }
    }

    // Logout clears cookie
    if (url.pathname === '/api/logout') {
      const h = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      h.set('Set-Cookie', SESSION.clear());
      return new Response(null, { status: 204, headers: h });
    }

    // Generic proxy to Azure for other /api/* calls
    if (url.pathname.startsWith('/api/')) {
      const path = url.pathname.replace(/^\/api\//, '');
      let resp;
      if (request.method === 'GET') {
        resp = await azure.get(path, { queryString: url.search.slice(1) });
      } else if (request.method === 'POST') {
        const buf = await request.arrayBuffer();
        resp = await azure.post(path, {
          queryString: url.search.slice(1),
          body: buf,
          headers: { 'content-type': request.headers.get('content-type') || 'application/json' }
        });
      } else {
        return new Response('Method Not Allowed', { status: 405, headers: { ...cors(origin) } });
      }
      const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      const ct = resp.headers?.get?.('content-type');
      if (ct) headers.set('content-type', ct);
      const data = resp.data ?? resp.raw ?? '';
      return new Response(typeof data === 'string' ? data : JSON.stringify(data), { status: resp.status || (resp.ok ? 200 : 502), headers });
    }

    // Public password page
    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('x-aa218-worker', 'password-page');
      return r;
    }

    // Test overrides
    const auth = url.searchParams.get('auth');
    if (auth === 'test-true') {
      const h = new Headers({ 'Cache-Control': 'no-store', 'x-aa218-worker': 'auth-test-true' });
      h.set('Set-Cookie', SESSION.set('1'));
      h.set('Location', stripParam(url.toString(), 'auth'));
      return new Response(null, { status: 302, headers: h });
    }
    if (auth === 'test-false') {
      const h = new Headers({ 'Cache-Control': 'no-store', 'x-aa218-worker': 'auth-test-false' });
      h.set('Set-Cookie', SESSION.clear());
      h.set('Location', `${url.origin}/password.html`);
      return new Response(null, { status: 302, headers: h });
    }

    // If session cookie exists, allow directly
    if (hasCookie(request)) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('x-aa218-worker', 'session-ok');
      return r;
    }

    // No cookie -> ask Azure if this request should pass
    const args = buildArgs(request, url);
    const gate = await azure.get('pingfn', { queryString: args });
    if (isPass(gate)) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('x-aa218-worker', 'azure-allow');
      return r;
    }

    return new Response(null, {
      status: 302,
      headers: { 'Location': `${url.origin}/password.html`, 'Cache-Control': 'no-store', 'x-aa218-worker': 'redirect-password' }
    });
  }
};
