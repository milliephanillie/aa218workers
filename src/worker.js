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

// Interpret PASS/FAIL from Azure response; also support {ok:true/false}
function isPass(apiResponse) {
    if (!apiResponse.ok) {
        return false;
    }

    // for now we just want to hardcode true as the return value
    return true;
}

export default {
    async fetch(request, env) {
        const requestUrl = new URL(request.url);
        const requestOrigin = request.headers.get('Origin') || '';
        const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });

        // CORS preflight for API routes
        if (requestUrl.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: createCorsHeaders(requestOrigin) });
        }

        // Login: browser POSTs here; Worker calls Azure (GET with query args), sets cookie on PASS
        if (requestUrl.pathname === '/api/login' && request.method === 'POST') {
            const filterArguments = buildFilterArguments(request, requestUrl);
            const azureResponse = await azureApi.get('pingfn', { queryString: filterArguments });
            const responseHeaders = new Headers({
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store',
                ...createCorsHeaders(requestOrigin)
            });
            const isAuthenticated = isPass(azureResponse);
            if (isAuthenticated) {
                responseHeaders.set('Set-Cookie', SESSION.set('1'));
            }
            const responseBody = azureResponse.data ?? azureResponse.raw ?? '';
            const loginResult = typeof responseBody === 'string' ? { ok: isAuthenticated, body: responseBody } : { ok: isAuthenticated, ...responseBody };
            return new Response(JSON.stringify(loginResult), { status: isAuthenticated ? 200 : 401, headers: responseHeaders });
        }

        // Logout: clear cookie
        if (requestUrl.pathname === '/api/logout') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Set-Cookie': SESSION.clear(),
                    'Cache-Control': 'no-store',
                    ...createCorsHeaders(requestOrigin)
                }
            });
        }

        // Generic proxy to Azure with key (GET/POST). Does NOT auto-set cookie.
        if (requestUrl.pathname.startsWith('/api/')) {
            const apiPath = requestUrl.pathname.replace(/^\/api\//, '');
            if (request.method === 'GET') {
                const apiResponse = await azureApi.get(apiPath, { queryString: requestUrl.search.slice(1) });
                const proxyHeaders = new Headers({
                    'Content-Type': apiResponse.headers.get('content-type') || 'application/json',
                    'Cache-Control': 'no-store',
                    ...createCorsHeaders(requestOrigin)
                });
                const responseBody = apiResponse.data ?? apiResponse.raw ?? '';
                return new Response(typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody), {
                    status: apiResponse.status,
                    headers: proxyHeaders
                });
            } else if (request.method === 'POST') {
                const requestBody = await request.arrayBuffer();
                const postResponse = await azureApi.post(apiPath, {
                    queryString: requestUrl.search.slice(1),
                    body: requestBody,
                    headers: {
                        'content-type': request.headers.get('content-type') || 'application/json'
                    }
                });
                const postHeaders = new Headers({
                    'Content-Type': postResponse.headers.get('content-type') || 'application/json',
                    'Cache-Control': 'no-store',
                    ...createCorsHeaders(requestOrigin)
                });
                const postResponseBody = postResponse.data ?? postResponse.raw ?? '';
                return new Response(typeof postResponseBody === 'string' ? postResponseBody : JSON.stringify(postResponseBody), {
                    status: postResponse.status,
                    headers: postHeaders
                });
            }
            return new Response('Method Not Allowed', { status: 405, headers: createCorsHeaders(requestOrigin) });
        }

        // Public password page
        if (requestUrl.pathname === '/password.html' || requestUrl.pathname.startsWith('/password/')) {
            const upstreamResponse = await fetch(request);
            const passwordPageResponse = new Response(upstreamResponse.body, upstreamResponse);
            passwordPageResponse.headers.set('Cache-Control', 'private, no-store');
            return passwordPageResponse;
        }

        // Gate everything else by cookie
        if (!SESSION.has(request)) {
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': `${requestUrl.origin}/password.html`,
                    'Cache-Control': 'no-store'
                }
            });
        }

        const upstreamResponse = await fetch(request);
        const authenticatedResponse = new Response(upstreamResponse.body, upstreamResponse);
        authenticatedResponse.headers.set('Cache-Control', 'private, no-store');
        return authenticatedResponse;
    }
};
