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

function createCorsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}

function hasSessionCookie(request, name = 'aa218_ok') {
  const cookie = request.headers.get('Cookie') || '';
  return cookie.split(/;\s*/).some(c => c.startsWith(`${name}=`));
}

function buildFilterArguments(request, url) {
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

function isFilterPassResponse(r) {
  // Your Azure function contract can be refined later
  if (!r) return false;
  if (typeof r.ok === 'boolean') return r.ok;
  // If we only have an HTTP status, 2xx == pass
  if (typeof r.status === 'number') return r.status >= 200 && r.status < 300;
  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const method = request.method;
    const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    const baseHeaders = (extra = {}) => ({
      'Cache-Control': 'no-store',
      'Vary': 'Cookie',
      'x-aa218-worker': 'v4',
      ...extra
    });

    // --- API preflight
    if (url.pathname.startsWith('/api/') && method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'preflight' }) } });
    }

    // --- API: login (explicit cookie set via password)
    if (url.pathname === '/api/login' && method === 'POST') {
      const headers = new Headers({ 'Content-Type': 'application/json', ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'login' }) });
      try {
        const body = await request.json();
        const submittedPassword = body?.password?.trim();
        if (!submittedPassword) return new Response(JSON.stringify({ ok: false, message: 'Password is required' }), { status: 400, headers });

        let ok = false;
        if (env.USE_AZURE_AUTH === 'true') {
          const args = buildFilterArguments(request, url);
          args.submittedPassword = submittedPassword;
          const ar = await azureApi.get('pingfn', { queryString: args });
          ok = isFilterPassResponse(ar);
        } else {
          ok = submittedPassword === (env.SITE_PASSWORD || '218club');
        }

        if (ok) {
          headers.set('Set-Cookie', SESSION.set('1'));
          return new Response(JSON.stringify({ ok: true, message: 'Authentication successful', ts: new Date().toISOString() }), { status: 200, headers });
        }
        return new Response(JSON.stringify({ ok: false, message: 'Invalid password', ts: new Date().toISOString() }), { status: 401, headers });
      } catch {
        return new Response(JSON.stringify({ ok: false, message: 'Invalid request format' }), { status: 400, headers });
      }
    }

    // --- API: logout
    if (url.pathname === '/api/logout') {
      return new Response(null, {
        status: 204,
        headers: { 'Set-Cookie': SESSION.clear(), ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'logout' }) }
      });
    }

    // --- Generic API proxy passthrough
    if (url.pathname.startsWith('/api/')) {
      const apiPath = url.pathname.replace(/^\/api\//, '');
      if (method === 'GET') {
        const ar = await azureApi.get(apiPath, { queryString: url.search.slice(1) });
        const headers = new Headers({ 'Content-Type': ar.headers?.get?.('content-type') || 'application/json', ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'api-get' }) });
        const body = ar.data ?? ar.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: ar.status || (ar.ok ? 200 : 502), headers });
      }
      if (method === 'POST') {
        const reqBody = await request.arrayBuffer();
        const pr = await azureApi.post(apiPath, { queryString: url.search.slice(1), body: reqBody, headers: { 'content-type': request.headers.get('content-type') || 'application/json' } });
        const headers = new Headers({ 'Content-Type': pr.headers?.get?.('content-type') || 'application/json', ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'api-post' }) });
        const body = pr.data ?? pr.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: pr.status || (pr.ok ? 200 : 502), headers });
      }
      return new Response('Method Not Allowed', { status: 405, headers: { ...createCorsHeaders(origin), ...baseHeaders({ 'x-aa218-worker': 'api-405' }) } });
    }

    // --- PUBLIC password page always allowed
    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('Vary', 'Cookie');
      r.headers.set('x-aa218-worker', 'password-page');
      return r;
    }

    // --- AUTH PARAMS (handled FIRST and without redirect for test-true)
    const authParam = url.searchParams.get('auth');

    if (authParam === 'test-true') {
      // Set cookie and serve the requested page WITHOUT redirect
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Set-Cookie', SESSION.set('1'));
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('Vary', 'Cookie');
      r.headers.set('x-aa218-worker', 'auth-param-set-no-redirect');
      return r;
    }

    if (authParam === 'test-false') {
      // Clear cookie and redirect to password page
      const headers = new Headers(baseHeaders({ 'x-aa218-worker': 'auth-param-clear-redirect' }));
      headers.set('Set-Cookie', SESSION.clear());
      headers.set('Location', `${url.origin}/password.html`);
      return new Response(null, { status: 302, headers });
    }

    // --- NO AUTH PARAM: GATE BY AZURE (or fallback to cookie if Azure disabled)
    if (env.USE_AZURE_AUTH === 'true') {
      const args = buildFilterArguments(request, url);
      try {
        const ar = await azureApi.get('pingfn', { queryString: args });
        const allowed = isFilterPassResponse(ar);
        if (!allowed) {
          return new Response(null, { status: 302, headers: baseHeaders({ Location: `${url.origin}/password.html`, 'x-aa218-worker': 'azure-deny' }) });
        }
        // allowed by Azure -> serve
        const upstream = await fetch(request);
        const r = new Response(upstream.body, upstream);
        r.headers.set('Cache-Control', 'private, no-store');
        r.headers.set('Vary', 'Cookie');
        r.headers.set('x-aa218-worker', 'azure-allow');
        return r;
      } catch (e) {
        // If Azure errors, be safe: deny
        return new Response(null, { status: 302, headers: baseHeaders({ Location: `${url.origin}/password.html`, 'x-aa218-worker': 'azure-error' }) });
      }
    } else {
      // Azure not enabled -> fallback to cookie gate
      if (!hasSessionCookie(request, 'aa218_ok')) {
        return new Response(null, { status: 302, headers: baseHeaders({ Location: `${url.origin}/password.html`, 'x-aa218-worker': 'cookie-deny' }) });
      }
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('Vary', 'Cookie');
      r.headers.set('x-aa218-worker', 'cookie-allow');
      return r;
    }
  }
};
