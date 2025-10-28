export class TecBaseApi {
    static METHODS = ['GET', 'POST'];
    static BASE_API_URL = 'https://218functionapp-c5ctf2ggfjcwdbax.centralus-01.azurewebsites.net';

    constructor({ functionsKey }) {
        this.functionsKey = functionsKey;
        this.baseUrl = new URL(TecBaseApi.BASE_API_URL);
    }

    requireKey() {
        if (!this.functionsKey) {
            throw new Error('Missing Azure Functions key');
        }
    }

    buildUrl(path, queryString) {
        const targetUrl = new URL(`/api/${path.replace(/^\/+/, '')}`, this.baseUrl);
        if (queryString && typeof queryString === 'string') {
            targetUrl.search = queryString.startsWith('?') ? queryString : `?${queryString}`;
        } else if (queryString && typeof queryString === 'object') {
            Object.entries(queryString).forEach(([key, value]) => targetUrl.searchParams.set(key, value ?? ''));
        }
        return targetUrl.toString();
    }

    async get(path, { queryString, headers = {} } = {}) {
        this.requireKey();
        const response = await fetch(this.buildUrl(path, queryString), {
            method: 'GET',
            headers: { ...headers, 'x-functions-key': this.functionsKey }
        });
        const responseText = await response.text();
        let parsedData = null;
        try {
            parsedData = responseText ? JSON.parse(responseText) : null;
        } catch {
            // Ignore parse errors
        }
        return { status: response.status, ok: response.ok, data: parsedData, raw: responseText, headers: response.headers };
    }

    async post(path, { queryString, body, headers = {} } = {}) {
        this.requireKey();
        const requestHeaders = new Headers(headers);
        if (!requestHeaders.get('content-type')) {
            requestHeaders.set('content-type', 'application/json');
        }
        requestHeaders.set('x-functions-key', this.functionsKey);
        const response = await fetch(this.buildUrl(path, queryString), { method: 'POST', headers: requestHeaders, body });
        const responseText = await response.text();
        let parsedData = null;
        try {
            parsedData = responseText ? JSON.parse(responseText) : null;
        } catch {
            // Ignore parse errors
        }
        return { status: response.status, ok: response.ok, data: parsedData, raw: responseText, headers: response.headers };
    }
}
