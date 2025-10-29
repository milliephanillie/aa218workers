export class TecCookie {
  constructor({ name, maxAge = 0, path = '/', domain = '', secure = true, httpOnly = true, sameSite = 'Lax' } = {}) {
    this.name = name; this.maxAge = maxAge; this.path = path; this.domain = domain;
    this.secure = secure; this.httpOnly = httpOnly; this.sameSite = sameSite;
  }

  parse(request) {
    const raw = request.headers.get('Cookie') || '';
    const out = {};
    for (const part of raw.split(';')) {
      const [n, ...v] = part.trim().split('=');
      if (n) out[n] = decodeURIComponent(v.join('='));
    }
    return out;
  }

  has(request) { return this.parse(request)[this.name] != null; }

  build(value, { maxAge = this.maxAge } = {}) {
    const parts = [`${this.name}=${encodeURIComponent(value)}`, `Path=${this.path}`];
    if (this.domain) parts.push(`Domain=${this.domain}`);
    if (maxAge > 0) { parts.push(`Max-Age=${maxAge}`); parts.push(`Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`); }
    if (maxAge === 0) { parts.push('Max-Age=0'); parts.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT'); }
    if (this.secure) parts.push('Secure');
    if (this.httpOnly) parts.push('HttpOnly');
    if (this.sameSite) parts.push(`SameSite=${this.sameSite}`);
    return parts.join('; ');
  }

  set(value = '1', options) { return this.build(value, options); }
  clear() { return this.build('', { maxAge: 0 }); }
}
