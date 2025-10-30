// worker.mjs — full file (re-coded as requested)
// - Keeps your existing behavior
// - /api/login now returns { ok, reason, response_azure, ts? }
// - Adds response headers X-Reason and X-Azure-Status (exposed via CORS)
// - Redirects HTML navigations without session to /password.html (unchanged intent)

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
    'Access-Control-Expose-Headers': 'X-Reason, X-Azure-Status',
    'Vary': 'Origin'
  };
}

function stripParam(u, key) {
  const url = new URL(u);
  url.searchParams.delete(key);
  return url.toString();
}

async function parseBody(request) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  const raw = await request.text();
  if (!raw || !raw.trim()) return {};
  if (ct.includes('application/json')) { try { return JSON.parse(raw); } catch { return {}; } }
  if (ct.includes('application/x-www-form-urlencoded')) {
    const p = new URLSearchParams(raw); const o = {}; for (const [k, v] of p.entries()) o[k] = v; return o;
  }
  try { return JSON.parse(raw); } catch { return {}; }
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

function ok2xx(res) {
  return !!res && typeof res.status === 'number' && res.status >= 200 && res.status < 300;
}

async function azureLogin(azure, args) {
  try {
    const g = await azure.get('pingfn', { queryString: args });
    return g;
  } catch (e) {
    const s = e?.status ?? 0;
    if (s === 404 || s === 405) {
      return await azure.post('pingfn', {
        queryString: '',
        body: JSON.stringify(args),
        headers: { 'content-type': 'application/json' }
      });
    }
    throw e;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const accept = (request.headers.get('Accept') || '').toLowerCase();
    const method = request.method;
    const isHtmlNav = (method === 'GET' || method === 'HEAD') && accept.includes('text/html');

    const azure = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY, baseUrl: env.AZURE_BASE_URL });

    // 1) CORS preflight for API
    if (url.pathname.startsWith('/api/') && method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...cors(origin), 'Cache-Control': 'no-store' } });
    }

    // 2) Manual test toggles
    const auth = url.searchParams.get('auth');
    if (auth === 'test-true') {
      const h = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      h.set('Set-Cookie', SESSION.set('1'));
      h.set('Location', stripParam(url.toString(), 'auth'));
      return new Response(null, { status: 302, headers: h });
    }
    if (auth === 'test-false') {
      const h = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      h.set('Set-Cookie', SESSION.clear());
      h.set('Location', `${url.origin}/password.html`);
      return new Response(null, { status: 302, headers: h });
    }

    // 3) Auth endpoints (reason + response_azure + debug headers)
    if (url.pathname === '/api/login' && method === 'POST') {
      const headers = new Headers({
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...cors(origin)
      });

      let bodyJson = {};
      try {
        bodyJson = await parseBody(request);
      } catch {
        const payload = { ok: false, reason: 'Body parse failed', response_azure: null };
        headers.set('X-Reason', 'Body parse failed');
        headers.set('X-Azure-Status', '0');
        return new Response(JSON.stringify(payload), { status: 400, headers });
      }

      const pw = (bodyJson.password || '').toString().trim();
      if (!pw) {
        const payload = { ok: false, reason: 'Password missing', response_azure: null };
        headers.set('X-Reason', 'Password missing');
        headers.set('X-Azure-Status', '0');
        return new Response(JSON.stringify(payload), { status: 400, headers });
      }

      const args = buildArgs(request, url);
      args.submittedPassword = pw;

      try {
        const res = await azureLogin(azure, args);
        const azureShape = {
          status: res?.status ?? 0,
          ok: !!(res && res.status >= 200 && res.status < 300),
          data: res?.data ?? null
        };

        if (!ok2xx(res)) {
          const payload = { ok: false, reason: 'Azure denied credentials', response_azure: azureShape };
          headers.set('X-Reason', 'Azure denied credentials');
          headers.set('X-Azure-Status', String(azureShape.status || 0));
          return new Response(JSON.stringify(payload), { status: res?.status || 401, headers });
        }

        headers.set('Set-Cookie', SESSION.set('1'));
        const payload = {
          ok: true,
          reason: 'Login success',
          ts: new Date().toISOString(),
          response_azure: azureShape
        };
        headers.set('X-Reason', 'Login success');
        headers.set('X-Azure-Status', String(azureShape.status || 200));
        return new Response(JSON.stringify(payload), { status: 200, headers });

      } catch (e) {
        const status = e?.status || 502;
        const azureShape = { status, ok: false, data: e?.data ?? (typeof e === 'string' ? e : null) };
        const payload = { ok: false, reason: 'Azure upstream error', response_azure: azureShape };
        headers.set('X-Reason', 'Azure upstream error');
        headers.set('X-Azure-Status', String(status));
        return new Response(JSON.stringify(payload), { status, headers });
      }
    }

    if (url.pathname === '/api/logout') {
      const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      headers.set('Set-Cookie', SESSION.clear());
      return new Response(null, { status: 204, headers });
    }

    // 4) API proxy passthrough
    if (url.pathname.startsWith('/api/')) {
      const path = url.pathname.replace(/^\/api\//, '');
      try {
        let proxied;
        if (method === 'GET') {
          proxied = await azure.get(path, { queryString: url.search.slice(1) });
        } else if (method === 'POST') {
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
      } catch (e) {
        const status = e?.status || 502;
        return new Response(JSON.stringify({ ok: false, message: 'Upstream error', status }), {
          status,
          headers: { ...cors(origin), 'Cache-Control': 'no-store', 'Content-Type': 'application/json' }
        });
      }
    }

    // 5) Allow password page without session
    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    // 6) Session check
    const cookie = request.headers.get('Cookie') || '';
    const hasSession = (typeof SESSION.has === 'function' ? SESSION.has(request) : cookie.includes('aa218_ok='));
    if (!hasSession && isHtmlNav) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': `${url.origin}/password.html`, 'Cache-Control': 'no-store' }
      });
    }

    // 7) Optional telemetry (ignore failures)
    if (hasSession) {
      try { await azure.get('pingfn', { queryString: buildArgs(request, url) }); } catch {}
    }

    // 8) Pass-through for everything else
    const upstream = await fetch(request);
    const response = new Response(upstream.body, upstream);
    response.headers.set('Cache-Control', 'private, no-store');
    return response;
  }
};
