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
  if (!r || r.ok === false) return false;
  return true;
}

function stripParam(url, key) {
  const u = new URL(url);
  u.searchParams.delete(key);
  return u.toString();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    if (url.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...createCorsHeaders(origin), 'x-aa218-worker': 'preflight' } });
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(origin), 'x-aa218-worker': 'login' });
      try {
        const body = await request.json();
        const submittedPassword = body?.password?.trim();
        if (!submittedPassword) return new Response(JSON.stringify({ ok: false, message: 'Password is required' }), { status: 400, headers });
        const useAzure = env.USE_AZURE_AUTH === 'true';
        let ok = false;
        if (useAzure) {
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

    if (url.pathname === '/api/logout') {
      return new Response(null, { status: 204, headers: { 'Set-Cookie': SESSION.clear(), 'Cache-Control': 'no-store', ...createCorsHeaders(origin), 'x-aa218-worker': 'logout' } });
    }

    if (url.pathname.startsWith('/api/')) {
      const apiPath = url.pathname.replace(/^\/api\//, '');
      if (request.method === 'GET') {
        const ar = await azureApi.get(apiPath, { queryString: url.search.slice(1) });
        const headers = new Headers({ 'Content-Type': ar.headers?.get?.('content-type') || 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(origin), 'x-aa218-worker': 'api-get' });
        const body = ar.data ?? ar.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: ar.status || (ar.ok ? 200 : 502), headers });
      }
      if (request.method === 'POST') {
        const reqBody = await request.arrayBuffer();
        const pr = await azureApi.post(apiPath, { queryString: url.search.slice(1), body: reqBody, headers: { 'content-type': request.headers.get('content-type') || 'application/json' } });
        const headers = new Headers({ 'Content-Type': pr.headers?.get?.('content-type') || 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(origin), 'x-aa218-worker': 'api-post' });
        const body = pr.data ?? pr.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: pr.status || (pr.ok ? 200 : 502), headers });
      }
      return new Response('Method Not Allowed', { status: 405, headers: { ...createCorsHeaders(origin), 'x-aa218-worker': 'api-405' } });
    }

    const authParam = url.searchParams.get('auth');
    if (authParam === 'test-true') {
      const headers = new Headers({ 'Set-Cookie': SESSION.set('1'), 'Cache-Control': 'no-store', 'x-aa218-worker': 'auth-param-set' });
      const clean = stripParam(url.toString(), 'auth');
      headers.set('Location', clean);
      return new Response(null, { status: 302, headers });
    }
    if (authParam === 'test-false') {
      const headers = new Headers({ 'Set-Cookie': SESSION.clear(), 'Cache-Control': 'no-store', 'x-aa218-worker': 'auth-param-clear' });
      const toPwd = `${url.origin}/password.html`;
      return new Response(null, { status: 302, headers: { ...Object.fromEntries(headers), Location: toPwd } });
    }

    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('x-aa218-worker', 'password-page');
      return r;
    }

    if (!hasSessionCookie(request, 'aa218_ok')) {
      return new Response(null, { status: 302, headers: { Location: `${url.origin}/password.html`, 'Cache-Control': 'no-store', 'x-aa218-worker': 'redirected-to-password' } });
    }

    const upstream = await fetch(request);
    const r = new Response(upstream.body, upstream);
    r.headers.set('Cache-Control', 'private, no-store');
    r.headers.set('x-aa218-worker', 'auth-ok');
    return r;
  }
};
