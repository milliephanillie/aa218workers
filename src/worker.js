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
function isFilterPassResponse(apiResponse, requestUrl = null) {
    console.log('=== FILTER RESPONSE EVALUATION ===');
    
    // Check for test authentication parameters
    if (requestUrl) {
        const authParam = requestUrl.searchParams.get('auth');
        if (authParam === 'test-false') {
            console.log('Test auth: forcing FAIL (test-false)');
            return false;
        }
        if (authParam === 'test-true') {
            console.log('Test auth: forcing PASS (test-true)');
            return true;
        }
    }

    console.log('API response status:', apiResponse.status);
    console.log('API response ok:', apiResponse.ok);
    console.log('API response data:', apiResponse.data);

    if (!apiResponse.ok) {
        console.log('Filter result: FAIL (API response not ok)');
        return false;
    }

    // For now we don't know of any other than the response status code
    console.log('Filter result: PASS (default behavior)');
    return true; // just hardcode to pass for now
}

export default {
    async fetch(request, env) {
        const requestUrl = new URL(request.url);
        const requestOrigin = request.headers.get('Origin') || '';
        const azureApi = new TecBaseApi({ functionsKey: env.AZ_FUNCTION_KEY });
        
        // Debug logging
        console.log('=== WORKER REQUEST START ===');
        console.log('URL:', requestUrl.href);
        console.log('Method:', request.method);
        console.log('Origin:', requestOrigin);
        console.log('Pathname:', requestUrl.pathname);
        console.log('Query params:', Object.fromEntries(requestUrl.searchParams));
        console.log('Has session cookie:', SESSION.has(request));

        // CORS preflight for API routes
        if (requestUrl.pathname.startsWith('/api/') && request.method === 'OPTIONS') {
            console.log('CORS preflight request handled');
            return new Response(null, { status: 204, headers: createCorsHeaders(requestOrigin) });
        }

        // Login: browser POSTs password here; Worker validates and sets cookie on success
        if (requestUrl.pathname === '/api/login' && request.method === 'POST') {
            console.log('=== LOGIN ATTEMPT ===');
            const responseHeaders = new Headers({
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store',
                ...createCorsHeaders(requestOrigin)
            });

            try {
                const loginData = await request.json();
                const submittedPassword = loginData?.password?.trim();
                console.log('Password submitted:', submittedPassword ? '***' : 'empty');
                console.log('Auth param:', requestUrl.searchParams.get('auth'));

                if (!submittedPassword) {
                    console.log('Login failed: No password provided');
                    return new Response(JSON.stringify({
                        ok: false,
                        message: 'Password is required',
                        debug: {
                            stage: 'password_validation',
                            error: 'no_password_provided'
                        }
                    }), {
                        status: 400,
                        headers: responseHeaders
                    });
                }

                // Check if we should use Azure validation or local password
                const useAzureValidation = env.USE_AZURE_AUTH === 'true';
                let isAuthenticated = false;
                console.log('Use Azure validation:', useAzureValidation);

                if (useAzureValidation) {
                    console.log('Using Azure Function validation');
                    // Use Azure Function for validation (original behavior)
                    const filterArguments = buildFilterArguments(request, requestUrl);
                    // Add password to the filter arguments
                    filterArguments.submittedPassword = submittedPassword;
                    
                    console.log('Calling Azure API with filter arguments');
                    const azureResponse = await azureApi.get('pingfn', { queryString: filterArguments });
                    console.log('Azure response status:', azureResponse.status);
                    console.log('Azure response ok:', azureResponse.ok);
                    isAuthenticated = isFilterPassResponse(azureResponse, requestUrl);
                    console.log('Final authentication result (Azure):', isAuthenticated);
                } else {
                    console.log('Using simple password validation');
                    // Check for test authentication parameters first
                    const authParam = requestUrl.searchParams.get('auth');
                    if (authParam === 'test-false') {
                        console.log('Test auth: forcing failure');
                        isAuthenticated = false;
                    } else if (authParam === 'test-true') {
                        console.log('Test auth: forcing success');
                        isAuthenticated = true;
                    } else {
                        // Simple password validation
                        const correctPassword = env.SITE_PASSWORD || '218club';
                        console.log('Checking password against:', correctPassword ? '***' : 'default');
                        isAuthenticated = submittedPassword === correctPassword;
                        console.log('Password match:', isAuthenticated);
                    }
                    console.log('Final authentication result (simple):', isAuthenticated);
                }

                if (isAuthenticated) {
                    console.log('Login SUCCESS - setting session cookie');
                    responseHeaders.set('Set-Cookie', SESSION.set('1'));
                    return new Response(JSON.stringify({
                        ok: true,
                        message: 'Authentication successful',
                        timestamp: new Date().toISOString(),
                        debug: {
                            stage: 'authentication_success',
                            useAzureValidation: useAzureValidation,
                            authParam: requestUrl.searchParams.get('auth'),
                            cookieSet: true
                        }
                    }), { 
                        status: 200, 
                        headers: responseHeaders 
                    });
                } else {
                    console.log('Login FAILED - invalid credentials');
                    return new Response(JSON.stringify({
                        ok: false,
                        message: 'Invalid password',
                        timestamp: new Date().toISOString(),
                        debug: {
                            stage: 'authentication_failed',
                            useAzureValidation: useAzureValidation,
                            authParam: requestUrl.searchParams.get('auth'),
                            passwordProvided: !!submittedPassword
                        }
                    }), { 
                        status: 401, 
                        headers: responseHeaders 
                    });
                }            } catch (parseError) {
                console.log('Login parse error:', parseError.message);
                return new Response(JSON.stringify({
                    ok: false,
                    message: 'Invalid request format',
                    debug: {
                        stage: 'request_parsing',
                        error: parseError.message
                    }
                }), {
                    status: 400,
                    headers: responseHeaders
                });
            }
        }

        // Logout: clear cookie
        if (requestUrl.pathname === '/api/logout') {
            console.log('=== LOGOUT REQUEST ===');
            console.log('Clearing session cookie');
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
            console.log('=== PASSWORD PAGE REQUEST ===');
            console.log('Serving password page');
            const upstreamResponse = await fetch(request);
            const passwordPageResponse = new Response(upstreamResponse.body, upstreamResponse);
            passwordPageResponse.headers.set('Cache-Control', 'private, no-store');
            return passwordPageResponse;
        }

        // Gate everything else by cookie
        if (!SESSION.has(request)) {
            console.log('=== ACCESS DENIED ===');
            console.log('No valid session cookie found - redirecting to password page');
            console.log('Redirect to:', `${requestUrl.origin}/password.html`);
            return new Response(null, {
                status: 302,
                headers: {
                    'Location': `${requestUrl.origin}/password.html`,
                    'Cache-Control': 'no-store'
                }
            });
        }

        console.log('=== AUTHENTICATED ACCESS ===');
        console.log('Valid session found - allowing access to:', requestUrl.pathname);
        const upstreamResponse = await fetch(request);
        const authenticatedResponse = new Response(upstreamResponse.body, upstreamResponse);
        authenticatedResponse.headers.set('Cache-Control', 'private, no-store');
        console.log('=== WORKER REQUEST END ===');
        return authenticatedResponse;
    }
};
