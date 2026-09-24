// Шлюз коннекторов MCP: единственная точка входа из интернета.
//
//   /.well-known/…            метаданные OAuth (сервер авторизации и ресурсы)
//   /authorize /token /register /revoke   сервер авторизации (oauth.js)
//   /  /signin /signout /password /grants/revoke   страницы владельца
//   /<коннектор>[/mcp]        MCP — только с токеном доступа для этого коннектора
//   /<коннектор>/<public>     адреса WebSocket с токеном внутри — без входа
//   /<коннектор>/…            остальные страницы коннектора — только владельцу
//
// Коннектору запрос уходит с общим секретом и тем, кто его прислал (X-Gateway-*).

import http from 'node:http';
import path from 'node:path';

import { OAuthError, OAuthServer } from './oauth.js';
import { OwnerAuth } from './owner.js';
import { newNonce, pageHeaders, renderConsent, renderHome, renderMessage, renderSignIn } from './pages.js';
import { forward, forwardUpgrade } from './proxy.js';

const FORM_LIMIT = 64 * 1024;
const JSON_LIMIT = 64 * 1024;
const REGISTER_PER_HOUR = 30;

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('Request body is too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function contentType(req) {
  return String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
}

// Тело формы или JSON → простой объект (для /token, /revoke).
async function readParams(req) {
  const text = await readBody(req, FORM_LIMIT);
  if (contentType(req) === 'application/json') {
    const obj = JSON.parse(text || '{}');
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new OAuthError('invalid_request', 'Expected a JSON object');
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, typeof v === 'string' ? v : String(v)]));
  }
  return Object.fromEntries(new URLSearchParams(text));
}

// Локальный путь для перенаправления после входа: только свои адреса. Управляющие
// символы и обратная косая черта отсекаются: браузер выбрасывает табуляцию из адреса,
// и «/<TAB>/evil.example» превратился бы в //evil.example.
function safeNext(value, origin) {
  const s = String(value ?? '');
  if (!s.startsWith('/') || [...s].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f || c === '\\')) return '/';
  let u;
  try {
    u = new URL(s, origin);
  } catch {
    return '/';
  }
  return u.origin === origin ? u.pathname + u.search : '/';
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export class Gateway {
  constructor({ config, logger, now = Date.now, fetchMetadata }) {
    this.config = config;
    this.logger = logger;
    this.owner = new OwnerAuth({ file: path.join(config.dataDir, 'owner.json'), logger, now });
    this.oauth = new OAuthServer({ config, owner: this.owner, logger, now, ...(fetchMetadata ? { fetchMetadata } : {}) });
    this.cookieName = config.https ? '__Host-gw' : 'gw';
    this.registrations = new Map(); // ip → [время]
    this.tunnels = new Set(); // открытые соединения WebSocket
    this.pruneTimer = setInterval(() => this.oauth.prune(), 3600_000);
    this.pruneTimer.unref?.();
  }

  // ---------- общее ----------

  clientIp(req) {
    if (this.config.trustProxy) {
      const real = req.headers['x-real-ip'];
      if (typeof real === 'string' && real) return real.trim();
    }
    return req.socket.remoteAddress ?? '?';
  }

  scheme(req) {
    if (this.config.trustProxy) {
      const p = String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim().toLowerCase();
      if (p === 'http' || p === 'https') return p;
    }
    return this.config.https ? 'https' : 'http';
  }

  baseHeaders() {
    const h = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' };
    if (this.config.https) h['Strict-Transport-Security'] = 'max-age=31536000';
    return h;
  }

  send(res, status, body, type = 'text/plain; charset=utf-8', headers = {}) {
    if (res.headersSent || res.destroyed) return;
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...this.baseHeaders(), ...headers });
    res.end(text);
  }

  json(res, status, body, headers = {}) {
    this.send(res, status, body, 'application/json', headers);
  }

  page(res, status, html, nonce, options) {
    if (res.headersSent || res.destroyed) return;
    res.writeHead(status, { ...pageHeaders(nonce, options), ...this.baseHeaders() });
    res.end(html);
  }

  message(res, status, title, text, link) {
    const nonce = newNonce();
    this.page(res, status, renderMessage({ nonce, title, text, link }), nonce);
  }

  redirect(res, location, status = 303) {
    if (res.headersSent) return;
    res.writeHead(status, { Location: location, 'Cache-Control': 'no-store', ...this.baseHeaders() });
    res.end();
  }

  // Запрос со своей страницы: Origin совпадает с адресом шлюза. Origin: null браузер
  // присылает, например, при строгой политике реферера — тогда решает Sec-Fetch-Site.
  sameOrigin(req) {
    const origin = req.headers.origin;
    if (origin && origin !== 'null') return origin === this.config.origin;
    return req.headers['sec-fetch-site'] === 'same-origin';
  }

  session(req) {
    const id = parseCookies(req.headers.cookie)[this.cookieName];
    return id ? { id, data: this.owner.session(id) } : null;
  }

  isOwner(req) {
    return Boolean(this.session(req)?.data);
  }

  setSessionCookie(res, id) {
    const attrs = [`${this.cookieName}=${id}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${12 * 3600}`];
    if (this.config.https) attrs.push('Secure');
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  clearSessionCookie(res) {
    const attrs = [`${this.cookieName}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
    if (this.config.https) attrs.push('Secure');
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  // Путь для журнала: длинные случайные сегменты (токены в адресах) скрыты.
  safePath(req) {
    return String(req.url ?? '')
      .split('?')[0]
      .replace(/\/([A-Za-z0-9_-]{16,})(?=\/|$)/g, '/…');
  }

  routeFor(pathname) {
    for (const r of this.config.routes) {
      if (pathname === r.path) return { route: r, sub: '' };
      if (pathname.startsWith(`${r.path}/`)) return { route: r, sub: pathname.slice(r.path.length) };
    }
    return null;
  }

  isPublic(route, sub) {
    return route.public.some((p) => sub === p || sub.startsWith(`${p}/`));
  }

  gatewayHeaders(req, auth, grantId = null, clientName = null) {
    const h = {
      host: req.headers.host,
      'x-gateway-secret': this.config.secret,
      'x-gateway-auth': auth,
      'x-real-ip': this.clientIp(req),
      'x-forwarded-proto': this.scheme(req),
      'x-forwarded-host': req.headers.host,
    };
    if (grantId) h['x-gateway-grant'] = grantId;
    if (clientName) h['x-gateway-client'] = encodeURIComponent(clientName);
    return h;
  }

  // ---------- вход ----------

  handler() {
    return (req, res) => {
      const started = Date.now();
      res.on('finish', () => {
        const ua = String(req.headers['user-agent'] ?? '').slice(0, 60);
        this.logger?.info(`${this.clientIp(req)} ${req.method} ${this.safePath(req)} → ${res.statusCode} ${Date.now() - started}ms ${ua}`);
      });
      this.route(req, res).catch((err) => {
        if (err instanceof SyntaxError) return this.json(res, 400, { error: 'invalid_request', error_description: 'Malformed request body' });
        if (err?.status === 413) return this.send(res, 413, 'Request body is too large\n');
        this.logger?.error(`${req.method} ${this.safePath(req)}: ${err?.stack ?? err}`);
        this.send(res, 500, 'Internal error\n');
      });
    };
  }

  // Проверки, общие для всех запросов: свой Host и HTTPS.
  precheck(req) {
    const host = String(req.headers.host ?? '').toLowerCase();
    if (host !== this.config.host) return { status: 421, text: 'Misdirected request' };
    if (this.config.https && this.scheme(req) !== 'https') return { status: 'https' };
    return null;
  }

  async route(req, res) {
    const problem = this.precheck(req);
    if (problem?.status === 'https') {
      if (req.method === 'GET' || req.method === 'HEAD') return this.redirect(res, `${this.config.origin}${req.url}`, 308);
      return this.send(res, 403, 'HTTPS is required\n');
    }
    if (problem) return this.send(res, problem.status, `${problem.text}\n`);
    const url = new URL(req.url, this.config.origin);
    const p = url.pathname;

    if (p.startsWith('/.well-known/')) return this.wellKnown(req, res, p);
    switch (p) {
      case '/authorize':
        return req.method === 'POST' ? this.authorizePost(req, res) : this.authorizeGet(req, res, url);
      case '/token':
        return this.tokenEndpoint(req, res);
      case '/register':
        return this.registerEndpoint(req, res);
      case '/revoke':
        return this.revokeEndpoint(req, res);
      case '/':
        return this.home(req, res);
      case '/signin':
        return this.signIn(req, res, url);
      case '/signout':
        return this.signOut(req, res);
      case '/password':
        return this.changePassword(req, res);
      case '/grants/revoke':
        return this.revokeFromHome(req, res);
      case '/robots.txt':
        return this.send(res, 200, 'User-agent: *\nDisallow: /\n');
      default:
    }
    const match = this.routeFor(p);
    if (!match) return this.send(res, 404, 'Not found\n');
    const { route, sub } = match;
    // Коннектору уходит нормализованный путь — тот, по которому выбран маршрут.
    const path = url.pathname + url.search;
    if (sub === '' || sub === '/' || sub === '/mcp' || sub === '/mcp/') return this.mcp(req, res, route, p, path);
    if (this.isPublic(route, sub)) return forward(req, res, route.upstream, this.gatewayHeaders(req, 'none'), { logger: this.logger, responseExtra: this.baseHeaders(), path });
    if (!this.isOwner(req)) {
      if (req.method === 'GET' || req.method === 'HEAD') return this.redirect(res, `/signin?next=${encodeURIComponent(url.pathname + url.search)}`);
      return this.send(res, 401, 'Sign in first\n');
    }
    if (!['GET', 'HEAD'].includes(req.method) && !this.sameOrigin(req)) return this.send(res, 403, 'Forbidden: cross-origin request\n');
    return forward(req, res, route.upstream, this.gatewayHeaders(req, 'owner'), { logger: this.logger, responseExtra: this.baseHeaders(), path });
  }

  upgradeHandler() {
    return (req, socket, head) => {
      socket.on('error', () => {});
      const reject = (status, text) => {
        const body = `${text}\n`;
        socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
      };
      const problem = this.precheck(req);
      if (problem) return reject(problem.status === 'https' ? 403 : problem.status, problem.status === 'https' ? 'HTTPS is required' : problem.text);
      let url;
      try {
        url = new URL(req.url, this.config.origin);
      } catch {
        return reject(400, 'Bad request');
      }
      const match = this.routeFor(url.pathname);
      // WebSocket — только на адреса с токеном внутри (оповещения, поток сообщений).
      if (!match || !this.isPublic(match.route, match.sub)) return reject(404, 'Not found');
      this.logger?.info(`${this.clientIp(req)} WS ${this.safePath(req)}`);
      forwardUpgrade(req, socket, head, match.route.upstream, this.gatewayHeaders(req, 'none'), {
        logger: this.logger,
        tunnels: this.tunnels,
        path: url.pathname + url.search,
      });
    };
  }

  // ---------- метаданные ----------

  wellKnown(req, res, p) {
    if (req.method === 'OPTIONS') return this.cors(res);
    if (req.method !== 'GET' && req.method !== 'HEAD') return this.send(res, 405, 'Method not allowed\n', undefined, { Allow: 'GET' });
    const cors = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=60' };
    if (p === '/.well-known/oauth-authorization-server' || p === '/.well-known/openid-configuration') {
      return this.json(res, 200, this.oauth.metadata(), cors);
    }
    const prm = '/.well-known/oauth-protected-resource';
    if (p === prm) return this.json(res, 200, this.oauth.resourceMetadata(this.config.origin, 'Все коннекторы'), cors);
    if (p.startsWith(`${prm}/`)) {
      const resourcePath = p.slice(prm.length).replace(/\/+$/, '');
      const match = this.routeFor(resourcePath);
      if (match && ['', '/mcp'].includes(match.sub)) {
        return this.json(res, 200, this.oauth.resourceMetadata(`${this.config.origin}${resourcePath}`, match.route.title), cors);
      }
    }
    return this.send(res, 404, 'Not found\n', undefined, { 'Access-Control-Allow-Origin': '*' });
  }

  cors(res) {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, MCP-Protocol-Version',
      'Access-Control-Max-Age': '600',
    });
    res.end();
  }

  // ---------- MCP ----------

  mcp(req, res, route, p, path) {
    const auth = String(req.headers.authorization ?? '');
    const bearer = /^bearer /i.test(auth) ? auth.slice(7).trim() : '';
    const result = this.oauth.authenticate(bearer, route);
    if (result.error) {
      const resourcePath = p.replace(/\/+$/, '');
      const params = [`resource_metadata="${this.config.origin}/.well-known/oauth-protected-resource${resourcePath}"`];
      if (result.error !== 'missing') params.unshift('error="invalid_token"', `error_description="${result.error === 'audience' ? 'The token was issued for another connector' : 'The access token is invalid or expired'}"`);
      if (bearer) this.logger?.info(`${route.path}: токен отклонён (${result.error})`);
      req.resume();
      return this.json(
        res,
        401,
        { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized: sign in to this connector (OAuth)' } },
        { 'WWW-Authenticate': `Bearer ${params.join(', ')}` },
      );
    }
    return forward(req, res, route.upstream, this.gatewayHeaders(req, 'token', result.grantId, result.grant.client_name), {
      logger: this.logger,
      responseExtra: this.baseHeaders(),
      path,
    });
  }

  // ---------- OAuth ----------

  authError(res, err) {
    if (!(err instanceof OAuthError)) throw err;
    const headers = { Pragma: 'no-cache', 'Access-Control-Allow-Origin': '*' };
    if (err.status === 401 && err.basic) headers['WWW-Authenticate'] = 'Basic realm="oauth"';
    return this.json(res, err.status, { error: err.error, error_description: err.message }, headers);
  }

  async authorizeGet(req, res, url) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return this.send(res, 405, 'Method not allowed\n');
    let started;
    try {
      started = await this.oauth.startAuthorization(url.searchParams);
    } catch (err) {
      if (!(err instanceof OAuthError)) throw err;
      if (err.redirectUri) {
        return this.redirect(res, this.oauth.redirectWith(err.redirectUri, { error: err.error, error_description: err.message, state: err.state }), 302);
      }
      this.logger?.warn(`запрос доступа отклонён: ${err.message}`);
      return this.message(res, 400, 'Не получилось подключить приложение', err.message);
    }
    return this.renderConsent(res, started.id, started.request, started.resourceInfo);
  }

  renderConsent(res, id, request, resourceInfo, error = '', status = 200) {
    const nonce = newNonce();
    const back = new URL(request.redirect_uri);
    const html = renderConsent({
      nonce,
      siteName: this.config.siteName,
      request: id,
      clientName: request.client_name,
      clientNote: request.client_source === 'cimd' ? `Проверено по адресу ${request.client_id}` : 'Приложение зарегистрировалось на этом сервере само',
      resourceTitle: resourceInfo?.title ?? request.resource,
      resourceUrl: request.resource ?? this.config.origin,
      returnTo: back.origin,
      knownReturn: this.oauth.isKnownReturn(request.redirect_uri),
      error,
    });
    // Chrome применяет form-action и к перенаправлению после отправки формы.
    this.page(res, status, html, nonce, { formAction: `'self' ${back.origin}` });
  }

  async authorizePost(req, res) {
    if (!this.sameOrigin(req)) return this.send(res, 403, 'Forbidden: cross-origin request\n');
    const form = new URLSearchParams(await readBody(req, FORM_LIMIT));
    const id = form.get('request') ?? '';
    const request = this.oauth.pendingRequest(id);
    if (!request) return this.message(res, 400, 'Запрос устарел', 'Страница разрешения открыта слишком давно или уже использована. Начните подключение в приложении заново.');
    if (form.get('decision') !== 'allow') return this.redirect(res, this.oauth.decide(id, false), 302);
    const check = await this.owner.check(form.get('password') ?? '', this.clientIp(req));
    if (!check.ok) {
      const error = check.retryAfter ? `Слишком много неверных попыток. Повторите через ${Math.ceil(check.retryAfter / 60)} мин.` : 'Неверный пароль.';
      return this.renderConsent(res, id, request, this.oauth.resourceInfo(request.resource), error, check.retryAfter ? 429 : 401);
    }
    // Разрешение даёт и вход владельца в браузере: следом обычно открывают настройки.
    this.setSessionCookie(res, this.owner.createSession());
    return this.redirect(res, this.oauth.decide(id, true), 302);
  }

  async tokenEndpoint(req, res) {
    if (req.method === 'OPTIONS') return this.cors(res);
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n', undefined, { Allow: 'POST' });
    try {
      const body = await readParams(req);
      const out = await this.oauth.token(req, body);
      return this.json(res, 200, out, { Pragma: 'no-cache', 'Access-Control-Allow-Origin': '*' });
    } catch (err) {
      if (err instanceof OAuthError) this.logger?.info(`/token: ${err.error} (${err.message})`);
      return this.authError(res, err);
    }
  }

  async registerEndpoint(req, res) {
    if (req.method === 'OPTIONS') return this.cors(res);
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n', undefined, { Allow: 'POST' });
    const ip = this.clientIp(req);
    const t = Date.now();
    const recent = (this.registrations.get(ip) ?? []).filter((x) => t - x < 3600_000);
    if (recent.length >= REGISTER_PER_HOUR) return this.json(res, 429, { error: 'invalid_request', error_description: 'Too many registrations' }, { 'Retry-After': '3600' });
    recent.push(t);
    this.registrations.set(ip, recent);
    if (this.registrations.size > 10_000) this.registrations.clear();
    try {
      const body = JSON.parse((await readBody(req, JSON_LIMIT)) || '{}');
      return this.json(res, 201, this.oauth.register(body), { 'Access-Control-Allow-Origin': '*' });
    } catch (err) {
      if (err instanceof OAuthError) this.logger?.info(`/register: ${err.error} (${err.message})`);
      return this.authError(res, err);
    }
  }

  async revokeEndpoint(req, res) {
    if (req.method === 'OPTIONS') return this.cors(res);
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n', undefined, { Allow: 'POST' });
    try {
      await this.oauth.revoke(req, await readParams(req));
      return this.send(res, 200, '', 'text/plain; charset=utf-8', { 'Access-Control-Allow-Origin': '*' });
    } catch (err) {
      return this.authError(res, err);
    }
  }

  // ---------- страницы владельца ----------

  home(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return this.send(res, 405, 'Method not allowed\n');
    const nonce = newNonce();
    if (!this.isOwner(req)) return this.page(res, 200, renderSignIn({ nonce, siteName: this.config.siteName, next: '/' }), nonce);
    const url = new URL(req.url, this.config.origin);
    const notices = { password: 'Пароль изменён.', revoked: 'Доступ отозван.' };
    const errors = { password: 'Пароль не изменён: проверьте текущий пароль и совпадение нового.', short: 'Новый пароль короче 12 символов.' };
    const html = renderHome({
      nonce,
      siteName: this.config.siteName,
      origin: this.config.origin,
      routes: this.config.routes,
      grants: this.oauth.grants(),
      notice: notices[url.searchParams.get('done')] ?? '',
      error: errors[url.searchParams.get('error')] ?? '',
    });
    return this.page(res, 200, html, nonce);
  }

  async signIn(req, res, url) {
    const nonce = newNonce();
    if (req.method === 'GET' || req.method === 'HEAD') {
      return this.page(res, 200, renderSignIn({ nonce, siteName: this.config.siteName, next: safeNext(url.searchParams.get('next'), this.config.origin) }), nonce);
    }
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n');
    if (!this.sameOrigin(req)) return this.send(res, 403, 'Forbidden: cross-origin request\n');
    const form = new URLSearchParams(await readBody(req, FORM_LIMIT));
    const next = safeNext(form.get('next'), this.config.origin);
    if (!this.owner.hasPassword()) {
      return this.page(res, 503, renderSignIn({ nonce, siteName: this.config.siteName, next, error: 'Пароль владельца ещё не задан: задайте его командой set-password на сервере.' }), nonce);
    }
    const check = await this.owner.check(form.get('password') ?? '', this.clientIp(req));
    if (!check.ok) {
      const error = check.retryAfter ? `Слишком много неверных попыток. Повторите через ${Math.ceil(check.retryAfter / 60)} мин.` : 'Неверный пароль.';
      return this.page(res, check.retryAfter ? 429 : 401, renderSignIn({ nonce, siteName: this.config.siteName, next, error }), nonce);
    }
    this.setSessionCookie(res, this.owner.createSession());
    return this.redirect(res, next);
  }

  signOut(req, res) {
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n');
    if (!this.sameOrigin(req)) return this.send(res, 403, 'Forbidden: cross-origin request\n');
    const s = this.session(req);
    if (s) this.owner.endSession(s.id);
    this.clearSessionCookie(res);
    return this.redirect(res, '/');
  }

  async changePassword(req, res) {
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n');
    if (!this.sameOrigin(req) || !this.isOwner(req)) return this.send(res, 403, 'Forbidden\n');
    const form = new URLSearchParams(await readBody(req, FORM_LIMIT));
    const next = form.get('password') ?? '';
    const check = await this.owner.check(form.get('current') ?? '', this.clientIp(req));
    if (!check.ok || next !== form.get('confirm')) return this.redirect(res, '/?error=password');
    if (next.length < 12) return this.redirect(res, '/?error=short');
    await this.owner.setPassword(next);
    // Все сессии сброшены: владелец входит заново с новым паролем.
    this.setSessionCookie(res, this.owner.createSession());
    this.logger?.info('пароль владельца изменён');
    return this.redirect(res, '/?done=password');
  }

  async revokeFromHome(req, res) {
    if (req.method !== 'POST') return this.send(res, 405, 'Method not allowed\n');
    if (!this.sameOrigin(req) || !this.isOwner(req)) return this.send(res, 403, 'Forbidden\n');
    const form = new URLSearchParams(await readBody(req, FORM_LIMIT));
    this.oauth.revokeGrant(form.get('grant') ?? '', 'отозван владельцем');
    return this.redirect(res, '/?done=revoked');
  }

  // ---------- запуск ----------

  async listen() {
    this.server = http.createServer(this.handler());
    this.server.on('upgrade', this.upgradeHandler());
    this.server.on('clientError', (err, socket) => socket.destroy());
    this.server.requestTimeout = 0;
    this.server.headersTimeout = 60_000;
    this.server.keepAliveTimeout = 65_000;
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.config.listen, () => {
        this.server.off('error', reject);
        resolve();
      });
    });
    return this.server.address();
  }

  async close() {
    clearInterval(this.pruneTimer);
    this.oauth.store.flush();
    for (const { socket, upSocket } of this.tunnels) {
      socket.destroy();
      upSocket.destroy();
    }
    this.server?.closeAllConnections?.();
    await new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }
}

