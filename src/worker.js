// worker.mjs — always returns JSON for /api/login (no blank bodies)

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
    // Expose debug headers in the browser:
    'Access-Control-Expose-Headers': 'X-Reason, X-Azure-Status, X-Request-Id',
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
  // Use the sneakin endpoint with philliepass header for password authentication
  const password = args.submittedPassword;
  return await azure.post('sneakin', {
    queryString: '',
    body: JSON.stringify(args),
    headers: { 
      'content-type': 'application/json',
      'philliepass': password
    }
  });
}

// Utility: Always-JSON response constructor for /api/login
function jsonLoginResponse(status, reason, payload = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  // Fill in debug headers if provided in payload
  if (payload.__origin) {
    const c = cors(payload.__origin);
    for (const [k, v] of Object.entries(c)) headers.set(k, v);
  }
  if (payload.__reason) headers.set('X-Reason', payload.__reason);
  if (payload.__azureStatus != null) headers.set('X-Azure-Status', String(payload.__azureStatus));
  if (payload.__reqId) headers.set('X-Request-Id', payload.__reqId);

  // Build final body
  const body = {
    ok: status >= 200 && status < 300,
    reason,
    request_azure: payload.request_azure ?? null,
    ts: new Date().toISOString(),
    response_azure: payload.response_azure ?? null,
    echo: payload.echo ?? null
  };
  return new Response(JSON.stringify(body), { status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const accept = (request.headers.get('Accept') || '').toLowerCase();
    const method = request.method;
    const isHtmlNav = (method === 'GET' || method === 'HEAD') && accept.includes('text/html');

    const azure = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY, baseUrl: env.AZURE_BASE_URL });

    // Preflight for API
    if (url.pathname.startsWith('/api/') && method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...cors(origin), 'Cache-Control': 'no-store' } });
    }

    // Manual test toggles
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

    // ======= HARDENED /api/login: ALWAYS RETURNS JSON BODY =======
    if (url.pathname === '/api/login' && method === 'POST') {
      const reqId = crypto.randomUUID?.() || String(Date.now());
      try {
        let bodyJson = {};
        try { bodyJson = await parseBody(request); }
        catch {
          return jsonLoginResponse(400, 'Body parse failed', {
            __origin: origin, __reason: 'Body parse failed', __azureStatus: 0, __reqId: reqId,
            request_azure: null, echo: null
          });
        }

        const pw = (bodyJson.password || '').toString().trim();
        if (!pw) {
          return jsonLoginResponse(400, 'Password missing', {
            __origin: origin, __reason: 'Password missing', __azureStatus: 0, __reqId: reqId,
            request_azure: null, echo: bodyJson
          });
        }

        const args = buildArgs(request, url);
        args.submittedPassword = pw;

        // Build request details for debugging
        const requestDetails = {
          method: 'POST',
          endpoint: 'sneakin',
          url: `${env.AZURE_BASE_URL}/api/sneakin`,
          headers: {
            'content-type': 'application/json',
            'philliepass': pw,
            'x-functions-key': '[REDACTED]'
          },
          body: args
        };

        let res;
        try {
          res = await azureLogin(azure, args);
        } catch (e) {
          const status = e?.status || 502;
          const azureShape = { status, ok: false, data: e?.data ?? (typeof e === 'string' ? e : null) };
          return jsonLoginResponse(status, 'Azure upstream error', {
            __origin: origin, __reason: 'Azure upstream error', __azureStatus: status, __reqId: reqId,
            request_azure: requestDetails, response_azure: azureShape, echo: bodyJson
          });
        }

        const azureShape = {
          status: res?.status ?? 0,
          ok: ok2xx(res),
          data: res?.data ?? null
        };

        if (!ok2xx(res)) {
          return jsonLoginResponse(res?.status || 401, 'Azure denied credentials', {
            __origin: origin, __reason: 'Azure denied credentials', __azureStatus: azureShape.status || 0, __reqId: reqId,
            request_azure: requestDetails, response_azure: azureShape, echo: bodyJson
          });
        }

        // Success → set cookie + JSON body
        const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
        headers.set('Set-Cookie', SESSION.set('1'));
        headers.set('Content-Type', 'application/json; charset=utf-8');
        headers.set('X-Reason', 'Login success');
        headers.set('X-Azure-Status', String(azureShape.status || 200));
        headers.set('X-Request-Id', reqId);

        const body = {
          ok: true,
          reason: 'Login success',
          request_azure: requestDetails,
          ts: new Date().toISOString(),
          response_azure: azureShape,
          echo: bodyJson
        };
        return new Response(JSON.stringify(body), { status: 200, headers });

      } catch (fatal) {
        // Top-level guard: even if something unexpected explodes, send JSON
        const status = 500;
        return jsonLoginResponse(status, 'Worker fatal error', {
          __origin: origin, __reason: 'Worker fatal error', __azureStatus: status, __reqId: reqId,
          request_azure: null, echo: null
        });
      }
    }
    // ======= END /api/login =======

    // /api/logout
    if (url.pathname === '/api/logout') {
      const headers = new Headers({ ...cors(origin), 'Cache-Control': 'no-store' });
      headers.set('Set-Cookie', SESSION.clear());
      return new Response(null, { status: 204, headers });
    }

    // API proxy passthrough
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

    // Allow password page without session
    if (url.pathname === '/password.html' || url.pathname.startsWith('/password/')) {
      const upstream = await fetch(request);
      const r = new Response(upstream.body, upstream);
      r.headers.set('Cache-Control', 'private, no-store');
      return r;
    }

    // Session gate for HTML navigations only
    const cookie = request.headers.get('Cookie') || '';
    const hasSession = (typeof SESSION.has === 'function' ? SESSION.has(request) : cookie.includes('aa218_ok='));
    if (!hasSession && isHtmlNav) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': `${url.origin}/password.html`, 'Cache-Control': 'no-store' }
      });
    }

    // Optional telemetry (non-blocking)
    if (hasSession) { try { await azure.get('pingfn', { queryString: buildArgs(request, url) }); } catch {} }

    // Pass-through for everything else
    const upstream = await fetch(request);
    const response = new Response(upstream.body, upstream);
    response.headers.set('Cache-Control', 'private, no-store');
    return response;
  }
};
