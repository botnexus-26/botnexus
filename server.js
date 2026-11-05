/**
 * BotNexus proxy  (proxy.js)
 * ============================================================
 * Host this on https://botnexus.apps.bot-hosting.cloud
 * (fi4.bot-hosting.cloud:25254, IP 65.21.202.154). Needs Node 18+.
 *
 * The static website lives on GitHub Pages (https://botnexus-26.github.io).
 * Its /dashboard page just redirects to this server. This server forwards
 * EVERYTHING it receives to the BotNexus bot, so the dashboard, Discord/Roblox
 * login callbacks, /api/*, and the Stripe webhook all work from one address.
 *
 *   browser ──► https://botnexus.apps.bot-hosting.cloud  ──► BOT_HOST:BOT_PORT
 *
 * No npm packages needed. Only Node's built-in http module is used.
 *
 * No environment variables are needed. The bot is already built in:
 *   bot (public API):  195.123.189.186:2728   e.g. http://195.123.189.186:2728/dashboard
 * This proxy listens on port 25254 (the port allocated by bot-hosting.cloud).
 *
 * Optional overrides (defaults shown):
 *   PORT          port this proxy listens on         (25254)
 *   BOT_HOST      bot address, "host" or "host:port"  (195.123.189.186)
 *   BOT_PORT      used when BOT_HOST has no port      (2728)
 *   PUBLIC_URL    public address of THIS proxy        (https://botnexus.apps.bot-hosting.cloud)
 *   STATUS_URL    status page for the offline page    (https://botnexus-status.xnetsite.xyz)
 *
 * Run:  node proxy.js
 */

'use strict';

const http = require('http');

// ============================================================
// CONFIG
// ============================================================

const PORT = Number(process.env.PORT) || 25254;
const BOT_PORT = Number(process.env.BOT_PORT) || 2728;

const PUBLIC_URL = String(
  process.env.PUBLIC_URL || 'https://botnexus-8lxu.onrender.com'
).trim().replace(/\/+$/, '');

const PUBLIC_HOST = PUBLIC_URL.replace(/^https?:\/\//i, '');

const STATUS_URL = String(
  process.env.STATUS_URL || 'https://botnexus.instatus.com'
).trim().replace(/\/+$/, '');

const MAX_PROXY_BODY_BYTES = 10 * 1024 * 1024;   // same as the bot's 10mb body limit
const UPSTREAM_TIMEOUT_MS = 30 * 1000;

function parseBotTarget(rawHost, fallbackPort) {

  let value = String(rawHost || '').trim() || 'http://195.123.189.234';

  value = value.replace(/^https?:\/\//i, '').replace(/\/+$/, '');

  const ipv6Match = value.match(/^\[([^\]]+)\](?::(\d+))?$/);

  if (ipv6Match) {
    return {
      hostname: ipv6Match[1],
      port: ipv6Match[2] ? Number(ipv6Match[2]) : fallbackPort
    };
  }

  const lastColon = value.lastIndexOf(':');

  if (lastColon > -1) {

    const possiblePort = value.slice(lastColon + 1);
    const possibleHost = value.slice(0, lastColon);

    if (/^\d+$/.test(possiblePort) && possibleHost) {

      const parsedPort = Number(possiblePort);

      if (parsedPort >= 1 && parsedPort <= 65535) {
        return { hostname: possibleHost, port: parsedPort };
      }
    }
  }

  return { hostname: value, port: fallbackPort };
}

const BOT_TARGET = parseBotTarget(process.env.BOT_HOST, BOT_PORT);
const BOT_HOST = BOT_TARGET.hostname;
const ACTUAL_BOT_PORT = BOT_TARGET.port;


// ============================================================
// HELPERS
// ============================================================

function isBotUnavailableError(error) {

  return [
    'ECONNREFUSED',
    'ECONNRESET',
    'ETIMEDOUT',
    'EHOSTUNREACH',
    'ENETUNREACH',
    'EPIPE',
    'ECONNABORTED'
  ].includes(error && error.code);
}

function isBrowserPageRequest(req) {

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return false;
  }

  const accept = String(req.headers.accept || '').toLowerCase();

  return (
    accept.includes('text/html') ||
    accept.includes('application/xhtml+xml') ||
    !accept
  );
}

// The host's reverse proxy (bot-hosting.cloud) adds the real client IP
// as the LAST entry of X-Forwarded-For.
function clientIp(req) {

  const forwarded = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);

  return forwarded.length
    ? forwarded[forwarded.length - 1]
    : (req.socket.remoteAddress || '');
}

function sendJson(res, status, body) {

  if (res.headersSent) {
    return res.end();
  }

  const payload = JSON.stringify(body);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store'
  });

  res.end(payload);
}

function setSecurityHeaders(res) {

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}


// ============================================================
// RATE LIMITING
// ============================================================

function createRateLimiter(maxRequests, windowMs) {

  const buckets = new Map();

  setInterval(() => {

    const now = Date.now();

    for (const [key, bucket] of buckets) {
      if (now - bucket.startedAt >= windowMs) {
        buckets.delete(key);
      }
    }

  }, Math.max(30000, windowMs)).unref();

  // Returns 0 if allowed, otherwise the Retry-After seconds.
  return function check(key) {

    const now = Date.now();
    let current = buckets.get(key);

    if (!current || now - current.startedAt >= windowMs) {
      buckets.set(key, { startedAt: now, count: 1 });
      return 0;
    }

    current.count += 1;

    if (current.count > maxRequests) {
      return Math.max(
        1,
        Math.ceil((windowMs - (now - current.startedAt)) / 1000)
      );
    }

    return 0;
  };
}

const generalLimit = createRateLimiter(600, 60 * 1000);
const authLimit = createRateLimiter(30, 60 * 1000);
const statusLimit = createRateLimiter(30, 60 * 1000);
const stripeLimit = createRateLimiter(100, 60 * 1000);


// ============================================================
// UNAVAILABLE PAGE (shown when the bot is offline)
// ============================================================

function escapeHtml(value) {

  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}


function createUnavailablePage() {

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <meta
        name="robots"
        content="noindex,nofollow"
    >

    <title>BotNexus — Temporarily Unavailable</title>

    <style>
        * {
            box-sizing: border-box;
        }

        html,
        body {
            margin: 0;
            min-height: 100%;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;

            background:
                radial-gradient(
                    circle at top,
                    rgba(14, 116, 144, 0.18),
                    transparent 38%
                ),
                #07111f;

            color: #f8fafc;

            font-family:
                Inter,
                ui-sans-serif,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }

        .wrapper {
            width: 100%;
            max-width: 680px;
        }

        .card {
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 24px;

            padding: 42px;

            background:
                rgba(10, 22, 38, 0.92);

            box-shadow:
                0 24px 80px rgba(0, 0, 0, 0.35);

            backdrop-filter: blur(18px);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 34px;
        }

        .brand-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #14b8a6;
            box-shadow:
                0 0 20px rgba(20, 184, 166, 0.65);
        }

        .brand-name {
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }

        .status {
            display: inline-flex;
            align-items: center;
            gap: 8px;

            padding: 7px 11px;

            border-radius: 999px;

            background:
                rgba(245, 158, 11, 0.10);

            color: #fbbf24;

            font-size: 13px;
            font-weight: 600;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: currentColor;
        }

        h1 {
            margin: 22px 0 14px;

            font-size:
                clamp(
                    30px,
                    6vw,
                    48px
                );

            line-height: 1.05;
            letter-spacing: -0.04em;
        }

        p {
            margin: 0;

            color: #94a3b8;

            font-size: 16px;
            line-height: 1.7;
        }

        .message {
            margin-top: 12px;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;

            margin-top: 30px;
        }

        a,
        button {
            appearance: none;

            border: 0;

            border-radius: 12px;

            padding:
                12px
                17px;

            font: inherit;
            font-size: 14px;
            font-weight: 700;

            cursor: pointer;

            text-decoration: none;

            transition:
                transform 0.15s ease,
                opacity 0.15s ease,
                background 0.15s ease;
        }

        a:hover,
        button:hover {
            transform: translateY(-1px);
        }

        .primary {
            background: #0d9488;
            color: white;
        }

        .primary:hover {
            background: #0f766e;
        }

        .secondary {
            background: rgba(148, 163, 184, 0.10);
            color: #e2e8f0;
        }

        .secondary:hover {
            background: rgba(148, 163, 184, 0.16);
        }

        .check {
            margin-top: 25px;

            color: #64748b;

            font-size: 13px;
        }

        #check-status {
            color: #94a3b8;
        }

        .footer {
            margin-top: 30px;

            padding-top: 20px;

            border-top:
                1px solid
                rgba(148, 163, 184, 0.10);

            color: #64748b;

            font-size: 12px;
            line-height: 1.6;
        }

        @media (max-width: 560px) {

            .card {
                padding: 28px;
                border-radius: 20px;
            }

            .actions {
                flex-direction: column;
            }

            a,
            button {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>

<body>

    <main class="wrapper">

        <section class="card">

            <div class="brand">

                <span class="brand-dot"></span>

                <span class="brand-name">
                    BotNexus
                </span>

            </div>

            <div class="status">
                <span class="status-dot"></span>
                Temporarily unavailable
            </div>

            <h1>
                BotNexus is currently unavailable.
            </h1>

            <p>
                The BotNexus service is not responding right now.
                This is usually temporary.
            </p>

            <p class="message">
                Check the live status page for updates, or try again
                once the service is back online.
            </p>

            <div class="actions">

                <a
                    class="primary"
                    href="${escapeHtml(STATUS_URL)}"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    Check Status
                </a>

                <button
                    class="secondary"
                    type="button"
                    onclick="retryNow()"
                >
                    Try Again
                </button>

            </div>

            <div class="check">
                <span id="check-status">
                    Checking automatically...
                </span>
            </div>

            <div class="footer">
                If the service is showing as operational on the status
                page but you are still seeing this message, wait a few
                seconds and try again.
            </div>

        </section>

    </main>

    <script>
        const returnTo =
            ${JSON.stringify('/dashboard')};

        let checking = false;

        async function checkBot() {

            if (checking) {
                return;
            }

            checking = true;

            const status =
                document.getElementById(
                    'check-status'
                );

            try {

                status.textContent =
                    'Checking BotNexus...';

                const response =
                    await fetch(
                        '/api/bot-status',
                        {
                            method: 'GET',
                            cache: 'no-store',
                            headers: {
                                'Accept':
                                    'application/json'
                            }
                        }
                    );

                if (
                    response.ok
                ) {

                    status.textContent =
                        'BotNexus is back online.';

                    window.location.href =
                        returnTo;

                    return;
                }

                status.textContent =
                    'BotNexus is still unavailable.';

            } catch {

                status.textContent =
                    'BotNexus is still unavailable.';
            } finally {

                checking = false;
            }
        }


        function retryNow() {
            window.location.reload();
        }


        checkBot();

        setInterval(
            checkBot,
            5000
        );
    </script>

</body>
</html>
`;
}

function sendBotUnavailable(req, res) {

  if (res.headersSent) {
    return res.end();
  }

  const page = createUnavailablePage();

  res.writeHead(503, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(page),
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Retry-After': '30',
    'X-Robots-Tag': 'noindex, nofollow'
  });

  res.end(req.method === 'HEAD' ? undefined : page);
}


// ============================================================
// BOT STATUS CHECK   (GET /api/bot-status)
// ============================================================

function checkBotAvailability() {

  return new Promise(resolve => {

    const request = http.request(
      {
        hostname: BOT_HOST,
        port: ACTUAL_BOT_PORT,
        path: '/',
        method: 'HEAD',
        timeout: 5000
      },
      response => {
        response.resume();
        resolve({ online: true });
      }
    );

    request.on('timeout', () => {
      request.destroy();
      resolve({ online: false });
    });

    request.on('error', () => resolve({ online: false }));

    request.end();
  });
}


// ============================================================
// PROXY
// ============================================================
//
// Pipes the request body straight through without parsing it, so the
// Stripe webhook (/api/stripe/webhook) keeps its exact raw body and
// signature verification still works on the bot.

function proxyToBot(req, res) {

  const targetPath = req.url || '/';

  const headers = { ...req.headers };

  for (const header of [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'upgrade',
    'host',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto'
  ]) {
    delete headers[header];
  }

  headers.host = `${BOT_HOST}:${ACTUAL_BOT_PORT}`;
  headers['x-forwarded-host'] = PUBLIC_HOST;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-port'] = '443';
  headers['x-forwarded-for'] = clientIp(req);

  const declaredLength = Number(req.headers['content-length']);

  if (Number.isFinite(declaredLength) && declaredLength > MAX_PROXY_BODY_BYTES) {
    return sendJson(res, 413, {
      ok: false,
      error: 'Request body is too large.'
    });
  }

  let timedOut = false;
  let tooLarge = false;

  const upstreamRequest = http.request(
    {
      hostname: BOT_HOST,
      port: ACTUAL_BOT_PORT,
      path: targetPath,
      method: req.method,
      headers
    },
    upstream => {

      if (res.headersSent) {
        upstream.resume();
        return;
      }

      res.statusCode = upstream.statusCode || 500;

      for (const [header, value] of Object.entries(upstream.headers)) {

        if (value === undefined) {
          continue;
        }

        // Point redirects at this proxy instead of the bot's raw address.
        if (header.toLowerCase() === 'location' && typeof value === 'string') {

          res.setHeader(
            'Location',
            value
              .replace(`http://${BOT_HOST}:${ACTUAL_BOT_PORT}`, PUBLIC_URL)
              .replace(`https://${BOT_HOST}:${ACTUAL_BOT_PORT}`, PUBLIC_URL)
          );

          continue;
        }

        res.setHeader(header, value);
      }

      upstream.pipe(res);
    }
  );

  upstreamRequest.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    timedOut = true;
    upstreamRequest.destroy();
  });

  let receivedBytes = 0;

  req.on('data', chunk => {

    receivedBytes += chunk.length;

    if (receivedBytes > MAX_PROXY_BODY_BYTES && !tooLarge) {

      tooLarge = true;
      upstreamRequest.destroy();

      sendJson(res, 413, {
        ok: false,
        error: 'Request body is too large.'
      });
    }
  });

  req.on('aborted', () => upstreamRequest.destroy());

  upstreamRequest.on('error', error => {

    if (tooLarge) {
      return;
    }

    const unavailable = isBotUnavailableError(error);

    if (unavailable) {
      console.warn(`[Proxy] Bot unavailable (${error.code}) for ${req.method} ${targetPath}`);
    } else {
      console.error(`[Proxy] Error for ${req.method} ${targetPath}: ${error.message}`);
    }

    if (res.headersSent) {
      return res.end();
    }

    if (timedOut || unavailable) {

      if (isBrowserPageRequest(req)) {
        return sendBotUnavailable(req, res);
      }

      return timedOut
        ? sendJson(res, 504, { ok: false, error: 'BotNexus took too long to respond.' })
        : sendJson(res, 503, { ok: false, error: 'BotNexus is currently unavailable.' });
    }

    return sendJson(res, 502, {
      ok: false,
      error: 'Could not connect to the BotNexus server.'
    });
  });

  req.pipe(upstreamRequest);
}


// ============================================================
// REQUEST HANDLER
// ============================================================

// Bots constantly probe for leaked secrets. None of these exist, so answer
// 404 right here instead of bothering the bot (and flooding the logs).
const SCANNER_PATH = new RegExp(
  '^/(' +
  '\\.(?!well-known)' +                  // any dotfile / dotfolder except /.well-known
  '|wp-|wordpress|phpinfo|info\\.php|php\\b|_profiler|vendor/' +
  '|composer\\.json|package\\.json|appsettings|aws-exports|secrets?\\b' +
  '|credentials|database\\.sql|sendgrid|openai\\.key|env(\\.|-|/|$)' +
  '|config(\\.|/)|settings\\.json|app\\.(js|config)|index\\.js|runtime-config' +
  '|nuxt\\.config|remix\\.config|auth\\.json|Dockerfile' +
  ')',
  'i'
);

const server = http.createServer((req, res) => {

  setSecurityHeaders(res);

  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  // ---- rate limiting ------------------------------------
  const ip = clientIp(req) || 'unknown';

  let retryAfter = 0;

  if (pathname === '/api/stripe/webhook') {
    retryAfter = stripeLimit(ip);
  } else if (pathname === '/api/bot-status') {
    retryAfter = statusLimit(ip);
  } else if (pathname.startsWith('/auth')) {
    retryAfter = authLimit(ip);
  } else {
    retryAfter = generalLimit(ip);
  }

  if (retryAfter) {
    res.setHeader('Retry-After', String(retryAfter));
    return sendJson(res, 429, {
      ok: false,
      error: 'Too many requests. Please try again shortly.'
    });
  }

  // ---- housekeeping routes ------------------------------
  if (pathname === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('User-agent: *\nDisallow: /\n');
  }

  if (pathname === '/favicon.ico' || pathname === '/sw.js') {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }

  if (SCANNER_PATH.test(pathname)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }

  // Root of the proxy host = the dashboard.
  if (pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    res.writeHead(302, { Location: '/dashboard', 'Cache-Control': 'no-store' });
    return res.end();
  }

  if (pathname === '/bot-unavailable') {
    return sendBotUnavailable(req, res);
  }

  if (pathname === '/api/bot-status') {

    return checkBotAvailability().then(result => {

      res.setHeader('Cache-Control', 'no-store');

      return result.online
        ? sendJson(res, 200, { ok: true, online: true })
        : sendJson(res, 503, { ok: false, online: false });
    });
  }

  // ---- everything else goes to the bot --------------------
  // (/dashboard, /auth, /api, /commands, /status, /why, /verification, ...)
  if (
    pathname === '/dashboard' ||
    pathname.startsWith('/dashboard/') ||
    pathname.startsWith('/auth') ||
    pathname.startsWith('/api/')
  ) {
    res.setHeader('Cache-Control', 'no-store');
  }

  return proxyToBot(req, res);
});

server.requestTimeout = 60 * 1000;

server.on('error', error => {

  console.error('[Proxy] HTTP server error:', error);

  if (error.code === 'EADDRINUSE') {
    console.error(`[Proxy] Port ${PORT} is already in use.`);
    process.exit(1);
  }
});

process.on('unhandledRejection', error => {
  console.error('[Proxy] Unhandled rejection:', error);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('============================================================');
  console.log('[Proxy] BotNexus proxy started');
  console.log(`[Proxy] Listening on  0.0.0.0:${PORT}`);
  console.log(`[Proxy] Public URL:   ${PUBLIC_URL}`);
  console.log(`[Proxy] Forwarding to ${BOT_HOST}:${ACTUAL_BOT_PORT}`);
  console.log('============================================================');
});
