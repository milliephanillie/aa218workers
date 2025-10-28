export class TecCookie {
    constructor({
        name,
        maxAge = 0,
        path = '/',
        domain = '',
        secure = true,
        httpOnly = true,
        sameSite = 'Lax'
    } = {}) {
        this.name = name;
        this.maxAge = maxAge;
        this.path = path;
        this.domain = domain;
        this.secure = secure;
        this.httpOnly = httpOnly;
        this.sameSite = sameSite;
    }

    parse(request) {
        const rawCookieString = request.headers.get('Cookie') || '';
        const parsedCookies = {};
        for (const cookiePart of rawCookieString.split(';')) {
            const [cookieName, ...cookieValueParts] = cookiePart.trim().split('=');
            if (cookieName) {
                parsedCookies[cookieName] = decodeURIComponent(cookieValueParts.join('='));
            }
        }
        return parsedCookies;
    }

    has(request) {
        return this.parse(request)[this.name] != null;
    }

    build(cookieValue, { maxAge = this.maxAge } = {}) {
        const cookieParts = [
            `${this.name}=${encodeURIComponent(cookieValue)}`,
            `Path=${this.path}`
        ];

        if (this.domain) {
            cookieParts.push(`Domain=${this.domain}`);
        }

        if (maxAge > 0) {
            cookieParts.push(`Max-Age=${maxAge}`);
            cookieParts.push(`Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`);
        }

        if (this.secure) {
            cookieParts.push('Secure');
        }

        if (this.httpOnly) {
            cookieParts.push('HttpOnly');
        }

        if (this.sameSite) {
            cookieParts.push(`SameSite=${this.sameSite}`);
        }

        return cookieParts.join('; ');
    }

    set(cookieValue = '1', options) {
        return this.build(cookieValue, options);
    }

    clear() {
        return this.build('', { maxAge: 0 });
    }
}
