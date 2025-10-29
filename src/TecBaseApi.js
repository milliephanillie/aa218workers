export class TecBaseApi {
  constructor({ functionsKey, baseUrl } = {}) {
    if (!functionsKey) throw new Error('Missing Azure Functions key');
    if (!baseUrl) throw new Error('Missing Azure Functions baseUrl');
    this.functionsKey = functionsKey;
    this.baseUrl = new URL(baseUrl);
  }

  buildUrl(path, query) {
    const url = new URL(`/api/${String(path).replace(/^\/+/, '')}`, this.baseUrl);
    if (typeof query === 'string' && query.trim()) {
      const s = query.startsWith('?') ? query.slice(1) : query;
      new URLSearchParams(s).forEach((v, k) => url.searchParams.set(k, v));
    } else if (query && typeof query === 'object') {
      Object.entries(query).forEach(([k, v]) => url.searchParams.set(k, v ?? ''));
    }
    url.searchParams.set('code', this.functionsKey);
    return url.toString();
  }

  async _request(method, path, { queryString, body, headers = {}, timeoutMs = 15000 } = {}) {
    const url = this.buildUrl(path, queryString);
    const h = new Headers(headers);
    if (method === 'POST' && !h.get('content-type')) h.set('content-type', 'application/json');
    h.set('x-functions-key', this.functionsKey);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort('timeout'), timeoutMs);
    let resp;
    try { resp = await fetch(url, { method, headers: h, body, signal: ctrl.signal }); } finally { clearTimeout(t); }
    const text = await resp.text();
    let json = null; try { json = text ? JSON.parse(text) : null; } catch {}
    if (resp.status === 404 || resp.status === 405) {
      const err = new Error(`HTTP ${resp.status}`);
      err.status = resp.status; err.data = json ?? text; err.headers = resp.headers; throw err;
    }
    return { status: resp.status, ok: resp.ok, data: json, raw: text, headers: resp.headers };
  }

  get(path, opts = {})  { return this._request('GET',  path, opts); }
  post(path, opts = {}) { return this._request('POST', path, opts); }
}
