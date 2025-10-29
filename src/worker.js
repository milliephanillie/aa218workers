import { TecBaseApi } from './TecBaseApi.js';

const COOKIE_NAME = 'aa218_ok';
const COOKIE_DOMAIN = '.aa218.club';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const ALLOWED_ORIGINS = ['https://aa218.club','https://www.aa218.club'];

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}

function buildSetCookie(value, { domain, maxAge=COOKIE_MAX_AGE, path='/', sameSite='Lax', secure=true, httpOnly=true } = {}) {
  const p = [`${COOKIE_NAME}=${value}`];
  if (maxAge != null) p.push(`Max-Age=${maxAge}`);
  p.push(`Path=${path}`);
  if (domain) p.push(`Domain=${domain}`);
  p.push(`SameSite=${sameSite}`);
  if (secure) p.push(`Secure`);
  if (httpOnly) p.push(`HttpOnly`);
  return p.join('; ');
}

function buildDeleteCookie({ domain, path='/' } = {}) {
  return `${COOKIE_NAME}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=${path}` + (domain ? `; Domain=${domain}` : '') + `; SameSite=Lax; Secure; HttpOnly`;
}

function setSession(headers) {
  headers.append('Set-Cookie', buildSetCookie('1', { domain: COOKIE_DOMAIN }));
  headers.append('Set-Cookie', buildSetCookie('1', {}));
}

function clearSession(headers) {
  headers.append('Set-Cookie', buildDeleteCookie({ domain: COOKIE_DOMAIN }));
  headers.append('Set-Cookie', buildDeleteCookie({}));
}

function hasSessionCookie(request) {
  const c = request.headers.get('Cookie') || '';
  return /(?:^|;\s*)aa218_ok=([^;]+)/.test(c);
}

function stripParam(u, key) {
  const x = new URL(u);
  x.searchParams.delete(key);
  return x.toString();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    if (url.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders(origin) });
      try {
        const body = await request.json();
        const pass = body?.password?.trim();
        if (!pass) return new Response(JSON.stringify({ ok:false, message:'Password is required' }), { status:400, headers });
        let ok = false;
        if (env.USE_AZURE_AUTH === 'true') {
          const args = {
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
            platform:'worker',
            major_version:'1',
            minor_version:'0',
            submittedPassword: pass
          };
          const r = await azureApi.get('pingfn', { queryString: args });
          ok = !!r?.ok;
        } else {
          ok = pass === (env.SITE_PASSWORD || '218club');
        }
        if (ok) {
          setSession(headers);
          return new Response(JSON.stringify({ ok:true }), { status:200, headers });
        }
        return new Response(JSON.stringify({ ok:false, message:'Invalid password' }), { status:401, headers });
      } catch {
        return new Response(JSON.stringify({ ok:false, message:'Invalid request format' }), { status:400, headers });
      }
    }

    if (url.pathname === '/api/logout') {
      const headers = new Headers({ 'Cache-Control':'no-store', ...corsHeaders(origin) });
      clearSession(headers);
      return new Response(null, { status:204, headers });
    }

    if (url.pathname.startsWith('/api/')) {
      const apiPath = url.pathname.replace(/^\/api\//, '');
      if (request.method === 'GET') {
        const r = await azureApi.get(apiPath, { queryString: url.search.slice(1) });
        const headers = new Headers({ 'Content-Type': r.headers?.get?.('content-type') || 'application/json', 'Cache-Control':'no-store', ...corsHeaders(origin) });
        const body = r.data ?? r.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: r.status || (r.ok ? 200 : 502), headers });
      }
      if (request.method === 'POST') {
        const reqBody = await request.arrayBuffer();
        const r = await azureApi.post(apiPath, { queryString: url.search.slice(1), body: reqBody, headers: { 'content-type': request.headers.get('content-type') || 'application/json' } });
        const headers = new Headers({ 'Content-Type': r.headers?.get?.('content-type') || 'application/json', 'Cache-Control':'no-store', ...corsHeaders(origin) });
        const body = r.data ?? r.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: r.status || (r.ok ? 200 : 502), headers });
      }
      return new Response('Method Not Allowed', { status:405, headers: corsHeaders(origin) });
    }

    const auth = url.searchParams.get('auth');
    if (auth === 'test-true') {
      const headers = new Headers({ 'Cache-Control':'no-store' });
      setSession(headers);
      headers.set('Location', stripParam(url.toString(), 'auth'));
      return new Response(null, { status:302, headers });
    }
    if (auth === 'test-false') {
      const headers = new Headers({ 'Cache-Control':'no-store' });
      clearSession(headers);
      headers.set('Location', `${url.origin}/password.html`);
      return new Response(null, { status:302, headers });
    }

    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    if (!hasSessionCookie(request)) {
      return new Response(null, { status:302, headers: { 'Location': `${url.origin}/password.html`, 'Cache-Control':'no-store' } });
    }

    const upstream = await fetch(request);
    const r = new Response(upstream.body, upstream);
    r.headers.set('Cache-Control', 'private, no-store');
    return r;
  }
};
