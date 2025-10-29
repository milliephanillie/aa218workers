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

function createCorsHeaders(requestOrigin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : '';
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

function buildFilterArguments(request, requestUrl) {
  return {
    clientRequestDateTime: new Date().toISOString(),
    visitorRemoteAddr: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '',
    visitorUserAgent: request.headers.get('User-Agent') || '',
    visitorQueryString: requestUrl.search.slice(1),
    visitorRequestAsset: requestUrl.pathname,
    visitorAccept: request.headers.get('Accept') || '',
    visitorAcceptEncoding: request.headers.get('Accept-Encoding') || '',
    visitorAcceptLanguage: request.headers.get('Accept-Language') || '',
    visitorReqMethod: request.method,
    visitorReferer: request.headers.get('Referer') || '',
    clientVar1: requestUrl.searchParams.get('cv1') || '',
    clientVar2: requestUrl.searchParams.get('cv2') || '',
    clientVar3: requestUrl.searchParams.get('cv3') || '',
    clientVar4: requestUrl.searchParams.get('cv4') || '',
    clientVar5: requestUrl.searchParams.get('cv5') || '',
    clientVar6: requestUrl.searchParams.get('cv6') || '',
    platform: 'worker',
    major_version: '1',
    minor_version: '0'
  };
}

function isFilterPassResponse(apiResponse) {
  if (!apiResponse || apiResponse.ok === false) return false;
  return true;
}

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);
    const requestOrigin = request.headers.get('Origin') || '';
    const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

    if (requestUrl.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'preflight' } });
    }

    if (requestUrl.pathname === '/api/login' && request.method === 'POST') {
      const responseHeaders = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'login' });
      try {
        const loginData = await request.json();
        const submittedPassword = loginData?.password?.trim();
        if (!submittedPassword) {
          return new Response(JSON.stringify({ ok: false, message: 'Password is required' }), { status: 400, headers: responseHeaders });
        }
        const useAzureValidation = env.USE_AZURE_AUTH === 'true';
        let isAuthenticated = false;
        if (useAzureValidation) {
          const args = buildFilterArguments(request, requestUrl);
          args.submittedPassword = submittedPassword;
          const azureResponse = await azureApi.get('pingfn', { queryString: args });
          isAuthenticated = isFilterPassResponse(azureResponse);
        } else {
          const correctPassword = env.SITE_PASSWORD || '218club';
          isAuthenticated = submittedPassword === correctPassword;
        }
        if (isAuthenticated) {
          responseHeaders.set('Set-Cookie', SESSION.set('1'));
          return new Response(JSON.stringify({ ok: true, message: 'Authentication successful', timestamp: new Date().toISOString() }), { status: 200, headers: responseHeaders });
        }
        return new Response(JSON.stringify({ ok: false, message: 'Invalid password', timestamp: new Date().toISOString() }), { status: 401, headers: responseHeaders });
      } catch {
        return new Response(JSON.stringify({ ok: false, message: 'Invalid request format' }), { status: 400, headers: responseHeaders });
      }
    }

    if (requestUrl.pathname === '/api/logout') {
      return new Response(null, { status: 204, headers: { 'Set-Cookie': SESSION.clear(), 'Cache-Control': 'no-store', ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'logout' } });
    }

    if (requestUrl.pathname.startsWith('/api/')) {
      const apiPath = requestUrl.pathname.replace(/^\/api\//, '');
      if (request.method === 'GET') {
        const apiResponse = await azureApi.get(apiPath, { queryString: requestUrl.search.slice(1) });
        const headers = new Headers({ 'Content-Type': apiResponse.headers?.get?.('content-type') || 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'api-get' });
        const body = apiResponse.data ?? apiResponse.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: apiResponse.status || (apiResponse.ok ? 200 : 502), headers });
      }
      if (request.method === 'POST') {
        const requestBody = await request.arrayBuffer();
        const postResponse = await azureApi.post(apiPath, { queryString: requestUrl.search.slice(1), body: requestBody, headers: { 'content-type': request.headers.get('content-type') || 'application/json' } });
        const headers = new Headers({ 'Content-Type': postResponse.headers?.get?.('content-type') || 'application/json', 'Cache-Control': 'no-store', ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'api-post' });
        const body = postResponse.data ?? postResponse.raw ?? '';
        return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: postResponse.status || (postResponse.ok ? 200 : 502), headers });
      }
      return new Response('Method Not Allowed', { status: 405, headers: { ...createCorsHeaders(requestOrigin), 'x-aa218-worker': 'api-405' } });
    }

    if (requestUrl.pathname === '/password.html' || requestUrl.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      r.headers.set('x-aa218-worker', 'password-page');
      return r;
    }

    if (!hasSessionCookie(request, 'aa218_ok')) {
      return new Response(null, { status: 302, headers: { Location: `${requestUrl.origin}/password.html`, 'Cache-Control': 'no-store', 'x-aa218-worker': 'redirected-to-password' } });
    }

    const upstream = await fetch(request);
    const r = new Response(upstream.body, upstream);
    r.headers.set('Cache-Control', 'private, no-store');
    r.headers.set('x-aa218-worker', 'auth-ok');
    return r;
  }
};
