# AA218 Workers

A Cloudflare Worker that provides authentication and API proxy functionality for the aa218.club website. This worker handles user authentication through Azure Functions, manages session cookies, and proxies API requests while enforcing access control.

## Overview

This project consists of three main components:

- **`worker.js`** - Main Cloudflare Worker that handles routing, authentication, and proxying
- **`TecBaseApi.js`** - API client for communicating with Azure Functions
- **`TecCookie.js`** - Cookie management utility for session handling

## Features

### Authentication System
- **Session-based authentication** using secure HTTP-only cookies
- **Azure Functions integration** for user validation via the `/api/pingfn` endpoint
- **Automatic redirects** to password page for unauthenticated users
- **Cookie-based gating** for all protected resources

### API Proxy
- **Transparent proxying** of API requests to Azure Functions
- **CORS handling** with support for specific allowed origins
- **GET and POST request support** with query string and body forwarding
- **Content-type preservation** and proper header handling

### Security Features
- **Origin validation** (aa218.club and www.aa218.club only)
- **Secure cookie configuration** (HttpOnly, Secure, SameSite=Lax)
- **30-day session expiration**
- **No-cache headers** on sensitive endpoints

## API Endpoints

### Authentication Endpoints

#### `POST /api/login`
Authenticates a user by calling the Azure Functions backend.
- Validates user credentials through Azure Functions
- Sets session cookie on successful authentication  
- Returns authentication result as JSON

#### `GET /api/logout`
Logs out the current user.
- Clears the session cookie
- Returns 204 No Content

### Proxy Endpoints

#### `GET|POST /api/{path}`
Proxies requests to Azure Functions backend.
- Forwards all query parameters and request body
- Preserves content-type headers
- Requires valid Azure Functions key
- Does not automatically set session cookies

### Public Endpoints

#### `GET /password.html`
Serves the public password/login page.
- Accessible without authentication
- Sets no-store cache headers

## Configuration

### Environment Variables

The worker requires the following environment variable:

- `AZ_FUNCTION_KEY` - Azure Functions authentication key

### Allowed Origins

The worker is configured to accept requests from:
- `https://aa218.club`
- `https://www.aa218.club`

### Azure Functions Base URL

The backend API is hosted at:
```
https://218functionapp-c5ctf2ggfjcwdbax.centralus-01.azurewebsites.net
```

## Usage

### Deployment

1. Set up the required environment variable in your Cloudflare Workers dashboard
2. Deploy the worker code to Cloudflare Workers
3. Configure your domain to route through the worker

### Integration

The worker automatically handles:
- Redirecting unauthenticated users to `/password.html`
- Setting session cookies upon successful login
- Proxying authenticated API requests to Azure Functions
- CORS headers for allowed origins

### Authentication Flow

1. User visits a protected page
2. If no valid session cookie exists, redirect to `/password.html`
3. User submits credentials via `POST /api/login`
4. Worker validates credentials with Azure Functions
5. On success, session cookie is set and user gains access
6. Subsequent requests are authenticated via cookie validation

## File Structure

```
├── worker.js           # Main Cloudflare Worker entry point
├── TecBaseApi.js       # Azure Functions API client
├── TecCookie.js        # Cookie management utility
└── README.md           # This file
```

## Technical Details

### Cookie Configuration
- **Name**: `aa218_ok`
- **Max Age**: 30 days (60 * 60 * 24 * 30 seconds)
- **Path**: `/` (site-wide)
- **Security**: HttpOnly, Secure, SameSite=Lax

### Response Interpretation
The worker interprets Azure Functions responses in multiple formats:
- Standard `{ok: boolean}` objects
- Legacy CFML result sets with `COLUMNS` and `DATA` arrays
- String responses containing "PASS"/"FAIL" indicators

### Error Handling
- Graceful JSON parsing with fallback to raw text
- Proper HTTP status codes (200, 401, 404, 405, etc.)
- CORS preflight handling for browser compatibility

## Development

### Local Testing
Since this is a Cloudflare Worker, use the Cloudflare Workers CLI (`wrangler`) for local development:

```bash
npm install -g wrangler
wrangler dev
```

### Dependencies
This worker uses native Web APIs and requires no external dependencies:
- Fetch API for HTTP requests
- URL API for URL manipulation
- Headers API for header management

## License

[Add your license information here]