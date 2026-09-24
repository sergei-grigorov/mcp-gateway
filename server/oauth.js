// Сервер авторизации OAuth 2.1 для коннекторов MCP (спецификация MCP 2025-11-25 и
// 2026-07-28): один на весь домен, издатель — сам адрес шлюза. Так Claude находит его
// при любом пути коннектора, даже если проигнорирует метаданные по пути.
//
// • Клиенты: документы метаданных по URL (CIMD — так подключаются Claude и Claude
//   Code; их документы встроены, потому что claude.ai бывает закрыт от запросов с
//   серверов) и динамическая регистрация (RFC 7591).
// • Адрес возврата — только Claude (claude.ai, claude.com) и loopback для локальных
//   приложений (Claude Code), плюс REDIRECT_URIS из настроек.
// • Код авторизации — только с PKCE S256, после ввода пароля владельца.
// • Токены непрозрачные, хранятся хешами (SHA-256). Токен обновления меняется при
//   каждом обновлении; старый ещё несколько минут принимается: запросы Claude приходят
//   с разных узлов и могут разойтись.
// • Токен привязан к ресурсу (RFC 8707): адрес коннектора или весь домен.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';

import { JsonFile, readJson } from './store.js';

export const KNOWN_CLIENTS = {
  'https://claude.ai/oauth/mcp-oauth-client-metadata': {
    client_name: 'Claude',
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    token_endpoint_auth_method: 'none',
  },
  'https://claude.ai/oauth/claude-code-client-metadata': {
    client_name: 'Claude Code',
    redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
    token_endpoint_auth_method: 'none',
  },
};
const CLAUDE_REDIRECTS = ['https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback'];
const AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'];
const CODE_TTL_MS = 5 * 60_000;
const PENDING_TTL_MS = 15 * 60_000;
const REFRESH_GRACE_MS = 10 * 60_000;
const MAX_REFRESH_PER_GRANT = 6;
const MAX_CLIENTS = 200;
const MAX_PENDING = 200;
const CIMD_TTL_MS = 5 * 60_000;
const CIMD_MAX_BYTES = 16 * 1024;

export class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const token = (prefix) => `${prefix}_${randomBytes(32).toString('base64url')}`;

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

export function isLoopback(url) {
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

// Адрес ресурса в каноническом виде (RFC 8707): схема и хост в нижнем регистре, без
// порта по умолчанию, без «/» в конце, без запроса и фрагмента.
export function canonicalResource(value) {
  let u;
  try {
    u = new URL(String(value));
  } catch {
    return null;
  }
  if (!['https:', 'http:'].includes(u.protocol) || u.hash || u.search || u.username || u.password) return null;
  // URL сам приводит схему и хост к нижнему регистру и убирает порт по умолчанию.
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

// Совпадение адреса возврата с зарегистрированным: точное, а у loopback — с любым портом
// (RFC 8252, OAuth 2.1 §8.4.2).
export function redirectMatches(registered, actual) {
  let r;
  let a;
  try {
    r = new URL(registered);
    a = new URL(actual);
  } catch {
    return false;
  }
  if (a.hash) return false;
  if (isLoopback(r) && isLoopback(a)) return r.hostname === a.hostname && r.pathname === a.pathname && r.search === a.search;
  return r.href === a.href;
}

function isPublicAddress(address) {
  const v4 = net.isIPv4(address) ? address : address.startsWith('::ffff:') && net.isIPv4(address.slice(7)) ? address.slice(7) : null;
  if (v4) {
    const [a, b] = v4.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && (b === 168 || b === 0)) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
  }
  const s = address.toLowerCase();
  if (s === '::' || s === '::1' || s.startsWith('fe80') || s.startsWith('fc') || s.startsWith('fd') || s.startsWith('ff')) return false;
  return net.isIPv6(address);
}

// Документ метаданных клиента по https-адресу (CIMD): только публичные адреса, без
// перенаправлений, небольшой размер, короткий таймаут.
export async function fetchClientMetadata(url, { timeoutMs = 5000 } = {}) {
  const u = new URL(url);
  const addresses = await dns.lookup(u.hostname, { all: true, verbatim: true });
  const good = addresses.find((a) => isPublicAddress(a.address));
  if (!good || addresses.some((a) => !isPublicAddress(a.address))) throw new Error('client_id host resolves to a non-public address');
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: `${u.pathname}${u.search}`,
        method: 'GET',
        headers: { Accept: 'application/json', 'User-Agent': 'mcp-gateway' },
        lookup: (_host, _opts, cb) => cb(null, good.address, good.family),
        timeout: timeoutMs,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`client metadata: HTTP ${res.statusCode}`));
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > CIMD_MAX_BYTES) {
            req.destroy(new Error('client metadata is too large'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new Error('client metadata is not JSON'));
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('client metadata: timeout')));
    req.on('error', reject);
    req.end();
  });
}

export class OAuthServer {
  constructor({ config, owner, logger, now = Date.now, fetchMetadata = fetchClientMetadata }) {
    this.config = config;
    this.owner = owner;
    this.logger = logger;
    this.now = now;
    this.fetchMetadata = fetchMetadata;
    this.store = new JsonFile(path.join(config.dataDir, 'oauth.json'), { defaults: { version: 1, clients: {}, grants: {}, access: {} }, logger });
    this.pending = new Map(); // id → запрос авторизации, ждущий решения владельца
    this.codes = new Map(); // хеш кода → { ... }
    this.cimd = new Map(); // client_id → { meta, until }
    this.prune();
  }

  get data() {
    return this.store.data;
  }

  // ---------- метаданные ----------

  metadata() {
    const o = this.config.origin;
    return {
      issuer: o,
      authorization_endpoint: `${o}/authorize`,
      token_endpoint: `${o}/token`,
      registration_endpoint: `${o}/register`,
      revocation_endpoint: `${o}/revoke`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: AUTH_METHODS,
      revocation_endpoint_auth_methods_supported: AUTH_METHODS,
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    };
  }

  // Метаданные защищённого ресурса (RFC 9728) для адреса коннектора или всего домена.
  resourceMetadata(resource, title) {
    return {
      resource,
      authorization_servers: [this.config.origin],
      bearer_methods_supported: ['header'],
      resource_name: title,
    };
  }

  // Ресурсы, которые шлюз знает: весь домен и адреса коннекторов (с /mcp и без).
  resources() {
    const o = this.config.origin;
    const out = new Map([[canonicalResource(o), { title: 'Все коннекторы', route: null }]]);
    for (const r of this.config.routes) {
      out.set(canonicalResource(o + r.path), { title: r.title, route: r });
      out.set(canonicalResource(`${o}${r.path}/mcp`), { title: r.title, route: r });
    }
    return out;
  }

  resourceInfo(resource) {
    if (resource === null || resource === undefined) return { title: 'Все коннекторы', route: null };
    return this.resources().get(resource) ?? null;
  }

  // Годится ли ресурс токена для коннектора route.
  audienceAllows(resource, route) {
    if (!resource || resource === canonicalResource(this.config.origin)) return true;
    const info = this.resources().get(resource);
    return Boolean(info?.route && info.route.path === route.path);
  }

  // ---------- клиенты ----------

  allowedRedirect(uri) {
    let u;
    try {
      u = new URL(uri);
    } catch {
      return false;
    }
    if (u.hash) return false;
    if (isLoopback(u)) return true;
    return [...CLAUDE_REDIRECTS, ...this.config.redirectUris].some((r) => redirectMatches(r, uri));
  }

  isKnownReturn(uri) {
    try {
      const u = new URL(uri);
      return isLoopback(u) || CLAUDE_REDIRECTS.some((r) => redirectMatches(r, uri));
    } catch {
      return false;
    }
  }

  // Клиент по client_id: зарегистрированный динамически или документ по URL.
  async client(clientId) {
    if (typeof clientId !== 'string' || !clientId) throw new OAuthError('invalid_client', 'client_id is required', 401);
    // Только собственные ключи: client_id вроде «__proto__» не должен найти прототип.
    const registered = Object.hasOwn(this.data.clients, clientId) ? this.data.clients[clientId] : null;
    if (registered) return { id: clientId, source: 'dcr', ...registered };
    if (!/^https:\/\//i.test(clientId)) throw new OAuthError('invalid_client', 'Unknown client_id', 401);
    const known = Object.hasOwn(KNOWN_CLIENTS, clientId) ? KNOWN_CLIENTS[clientId] : null;
    if (known) return { id: clientId, source: 'cimd', ...known };
    const cached = this.cimd.get(clientId);
    if (cached && cached.until > this.now()) return { id: clientId, source: 'cimd', ...cached.meta };
    let u;
    try {
      u = new URL(clientId);
    } catch {
      throw new OAuthError('invalid_client', 'client_id is not a valid URL', 401);
    }
    if (u.username || u.password || u.hash || u.pathname === '/' || /\/\.\.?(\/|$)/.test(u.pathname)) {
      throw new OAuthError('invalid_client', 'client_id URL is not a valid metadata document URL', 401);
    }
    let doc;
    try {
      doc = await this.fetchMetadata(clientId);
    } catch (err) {
      throw new OAuthError('invalid_client', `Could not load client metadata: ${err.message}`, 401);
    }
    if (doc?.client_id !== clientId || !Array.isArray(doc.redirect_uris) || !doc.redirect_uris.length || typeof doc.client_name !== 'string') {
      throw new OAuthError('invalid_client', 'Client metadata document is invalid', 401);
    }
    const method = doc.token_endpoint_auth_method ?? 'none';
    if (method !== 'none') throw new OAuthError('invalid_client', 'Client metadata documents are for public clients only', 401);
    const meta = { client_name: doc.client_name.slice(0, 100), redirect_uris: doc.redirect_uris.map(String), token_endpoint_auth_method: 'none' };
    this.cimd.set(clientId, { meta, until: this.now() + CIMD_TTL_MS });
    return { id: clientId, source: 'cimd', ...meta };
  }

  // Динамическая регистрация (RFC 7591).
  register(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new OAuthError('invalid_client_metadata', 'Expected a JSON object');
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || uris.some((u) => typeof u !== 'string')) {
      throw new OAuthError('invalid_redirect_uri', 'redirect_uris must be a non-empty array of URLs');
    }
    for (const u of uris) {
      if (!this.allowedRedirect(u)) {
        throw new OAuthError('invalid_redirect_uri', `Redirect URI is not allowed on this server: ${u}. Allowed: Claude (claude.ai) and local apps (http://localhost).`);
      }
    }
    const method = body.token_endpoint_auth_method ?? 'client_secret_basic';
    if (!AUTH_METHODS.includes(method)) throw new OAuthError('invalid_client_metadata', `token_endpoint_auth_method must be one of: ${AUTH_METHODS.join(', ')}`);
    const grantTypes = (Array.isArray(body.grant_types) ? body.grant_types : ['authorization_code']).filter((g) => ['authorization_code', 'refresh_token'].includes(g));
    if (!grantTypes.includes('authorization_code')) grantTypes.unshift('authorization_code');
    const clientName = typeof body.client_name === 'string' && body.client_name.trim() ? body.client_name.trim().slice(0, 100) : 'Без названия';
    const id = `dcr_${randomBytes(16).toString('base64url')}`;
    const secret = method === 'none' ? null : `gws_${randomBytes(32).toString('base64url')}`;
    const t = this.now();
    this.data.clients[id] = {
      client_name: clientName,
      redirect_uris: uris,
      token_endpoint_auth_method: method,
      grant_types: grantTypes,
      secret_hash: secret ? sha256(secret) : null,
      created_at: t,
      last_used_at: t,
    };
    this.evictClients();
    this.store.save();
    this.logger?.info(`регистрация клиента «${clientName}» (${method}), возврат: ${uris.join(', ')}`);
    const out = {
      client_id: id,
      client_id_issued_at: Math.floor(t / 1000),
      client_name: clientName,
      redirect_uris: uris,
      token_endpoint_auth_method: method,
      grant_types: grantTypes,
      response_types: ['code'],
    };
    if (secret) Object.assign(out, { client_secret: secret, client_secret_expires_at: 0 });
    return out;
  }

  evictClients() {
    const entries = Object.entries(this.data.clients);
    if (entries.length <= MAX_CLIENTS) return;
    const inUse = new Set(Object.values(this.data.grants).map((g) => g.client_id));
    entries
      .filter(([id]) => !inUse.has(id))
      .sort((a, b) => a[1].last_used_at - b[1].last_used_at)
      .slice(0, entries.length - MAX_CLIENTS)
      .forEach(([id]) => delete this.data.clients[id]);
  }

  // Аутентификация клиента на /token и /revoke: client_secret_basic, client_secret_post
  // или публичный клиент (только client_id).
  async authenticateClient(req, body) {
    let clientId = body.client_id;
    let secret = body.client_secret;
    const auth = String(req.headers.authorization ?? '');
    let basic = false;
    if (/^basic /i.test(auth)) {
      const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i < 0) throw new OAuthError('invalid_client', 'Malformed Basic credentials', 401);
      try {
        clientId = decodeURIComponent(decoded.slice(0, i).replace(/\+/g, ' '));
        secret = decodeURIComponent(decoded.slice(i + 1).replace(/\+/g, ' '));
      } catch {
        throw new OAuthError('invalid_client', 'Malformed Basic credentials', 401);
      }
      basic = true;
      if (body.client_id && body.client_id !== clientId) throw new OAuthError('invalid_client', 'client_id mismatch', 401);
    }
    const client = await this.client(clientId);
    if (client.secret_hash) {
      if (typeof secret !== 'string' || !safeEqual(sha256(secret), client.secret_hash)) {
        throw Object.assign(new OAuthError('invalid_client', 'Client authentication failed', 401), { basic });
      }
    }
    return client;
  }

  // ---------- авторизация ----------

  // Разбор запроса /authorize. Ошибки клиента и адреса возврата показываются
  // владельцу (перенаправлять на непроверенный адрес нельзя), остальные уходят
  // приложению через адрес возврата.
  async startAuthorization(params) {
    const client = await this.client(params.get('client_id'));
    let redirectUri = params.get('redirect_uri');
    if (!redirectUri) {
      if (client.redirect_uris.length !== 1) throw new OAuthError('invalid_request', 'redirect_uri is required');
      redirectUri = client.redirect_uris[0];
    }
    const registered = client.redirect_uris.some((r) => redirectMatches(r, redirectUri));
    // Документ Claude встроен: новые адреса возврата Claude тоже принимаются.
    const claudeLike = KNOWN_CLIENTS[client.id] && this.allowedRedirect(redirectUri);
    if ((!registered && !claudeLike) || !this.allowedRedirect(redirectUri)) {
      throw new OAuthError('invalid_request', `Redirect URI is not registered for this client or not allowed on this server: ${redirectUri}`);
    }
    const state = params.get('state');
    const fail = (error, description) => {
      throw Object.assign(new OAuthError(error, description), { redirectUri, state });
    };
    if (params.get('response_type') !== 'code') fail('unsupported_response_type', 'Only response_type=code is supported');
    const challenge = params.get('code_challenge');
    if (!challenge || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) fail('invalid_request', 'PKCE code_challenge is required');
    if ((params.get('code_challenge_method') ?? 'plain') !== 'S256') fail('invalid_request', 'code_challenge_method must be S256');
    let resource = null;
    const resources = params.getAll('resource');
    if (resources.length > 1) fail('invalid_target', 'Only one resource is supported');
    if (resources.length) {
      resource = canonicalResource(resources[0]);
      if (!resource || !this.resources().has(resource)) fail('invalid_target', `Unknown resource: ${resources[0]}`);
    }
    this.prunePending();
    const id = randomBytes(24).toString('base64url');
    this.pending.set(id, {
      client_id: client.id,
      client_name: client.client_name,
      client_source: client.source,
      redirect_uri: redirectUri,
      state,
      code_challenge: challenge,
      scope: params.get('scope') ?? null,
      resource,
      created: this.now(),
    });
    this.logger?.info(`запрос доступа: «${client.client_name}» → ${resource ?? 'все коннекторы'}`);
    return { id, request: this.pending.get(id), resourceInfo: this.resourceInfo(resource) };
  }

  pendingRequest(id) {
    this.prunePending();
    return this.pending.get(id) ?? null;
  }

  prunePending() {
    const t = this.now();
    for (const [id, p] of this.pending) if (t - p.created > PENDING_TTL_MS) this.pending.delete(id);
    while (this.pending.size > MAX_PENDING) this.pending.delete(this.pending.keys().next().value);
  }

  // Адрес возврата с параметрами ответа (RFC 6749 §4.1.2, RFC 9207: iss).
  redirectWith(redirectUri, params) {
    const u = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined) u.searchParams.set(k, v);
    u.searchParams.set('iss', this.config.origin);
    return u.href;
  }

  // Решение владельца. allow — выдать код и вернуть адрес для перенаправления.
  decide(id, allow) {
    const p = this.pending.get(id);
    if (!p) return null;
    this.pending.delete(id);
    if (!allow) {
      this.logger?.info(`доступ отклонён: «${p.client_name}»`);
      return this.redirectWith(p.redirect_uri, { error: 'access_denied', error_description: 'The owner denied access', state: p.state });
    }
    const code = randomBytes(32).toString('base64url');
    this.codes.set(sha256(code), { ...p, issued: this.now(), used: false, grant: null });
    for (const [h, c] of this.codes) if (this.now() - c.issued > CODE_TTL_MS) this.codes.delete(h);
    return this.redirectWith(p.redirect_uri, { code, state: p.state });
  }

  // ---------- токены ----------

  async token(req, body) {
    const grantType = body.grant_type;
    if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
      throw new OAuthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
    }
    const client = await this.authenticateClient(req, body);
    if (grantType === 'authorization_code') return this.exchangeCode(client, body);
    return this.refresh(client, body);
  }

  checkResource(requested, bound) {
    if (requested === undefined || requested === null || requested === '') return;
    const r = canonicalResource(requested);
    if (!r || !this.resources().has(r)) throw new OAuthError('invalid_target', `Unknown resource: ${requested}`);
    // Токен на весь домен можно сузить до коннектора; наоборот — нельзя.
    if (bound && r !== bound) throw new OAuthError('invalid_target', 'resource does not match the authorization');
  }

  exchangeCode(client, body) {
    const code = String(body.code ?? '');
    const h = sha256(code);
    const c = this.codes.get(h);
    if (!c || this.now() - c.issued > CODE_TTL_MS) throw new OAuthError('invalid_grant', 'Authorization code is invalid or expired');
    if (c.used) {
      // Повторное использование кода: выданный по нему доступ отзывается (RFC 6749 §4.1.2).
      if (c.grant) this.revokeGrant(c.grant, 'код авторизации использован повторно');
      this.codes.delete(h);
      throw new OAuthError('invalid_grant', 'Authorization code was already used');
    }
    if (c.client_id !== client.id) throw new OAuthError('invalid_grant', 'Authorization code was issued to another client');
    // Дальше код одноразовый при любом исходе: неудачная проверка PKCE его тоже сжигает.
    c.used = true;
    if (body.redirect_uri !== undefined && body.redirect_uri !== c.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri does not match');
    const verifier = String(body.code_verifier ?? '');
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new OAuthError('invalid_grant', 'code_verifier is missing or malformed');
    const computed = createHash('sha256').update(verifier).digest('base64url');
    if (!safeEqual(computed, c.code_challenge)) throw new OAuthError('invalid_grant', 'PKCE verification failed');
    this.checkResource(body.resource, c.resource);
    const resource = c.resource ?? (body.resource ? canonicalResource(body.resource) : null);
    const grantId = randomBytes(12).toString('base64url');
    const t = this.now();
    this.data.grants[grantId] = {
      client_id: client.id,
      client_name: client.client_name,
      resource,
      scope: c.scope,
      created_at: t,
      last_used_at: t,
      refresh: [],
    };
    c.grant = grantId;
    if (this.data.clients[client.id]) this.data.clients[client.id].last_used_at = t;
    this.logger?.info(`доступ выдан: «${client.client_name}» → ${resource ?? 'все коннекторы'}`);
    return this.issue(grantId);
  }

  refresh(client, body) {
    const h = sha256(String(body.refresh_token ?? ''));
    const t = this.now();
    for (const [grantId, g] of Object.entries(this.data.grants)) {
      const entry = g.refresh.find((r) => r.hash === h);
      if (!entry) continue;
      if (g.client_id !== client.id) throw new OAuthError('invalid_grant', 'Refresh token was issued to another client');
      if (entry.expires_at < t) throw new OAuthError('invalid_grant', 'Refresh token expired');
      if (entry.used_at && t - entry.used_at > REFRESH_GRACE_MS) throw new OAuthError('invalid_grant', 'Refresh token was already used');
      this.checkResource(body.resource, g.resource);
      entry.used_at ??= t;
      return this.issue(grantId);
    }
    throw new OAuthError('invalid_grant', 'Refresh token is invalid');
  }

  issue(grantId) {
    const g = this.data.grants[grantId];
    const t = this.now();
    const access = token('gwa');
    const refresh = token('gwr');
    this.data.access[sha256(access)] = { grant: grantId, expires_at: t + this.config.accessTtlSec * 1000 };
    g.refresh.push({ hash: sha256(refresh), expires_at: t + this.config.refreshTtlSec * 1000, used_at: null });
    g.refresh = g.refresh.slice(-MAX_REFRESH_PER_GRANT);
    g.last_used_at = t;
    this.store.save();
    const out = { access_token: access, token_type: 'Bearer', expires_in: this.config.accessTtlSec, refresh_token: refresh };
    if (g.scope) out.scope = g.scope;
    return out;
  }

  revokeGrant(grantId, why = 'отозван') {
    if (!Object.hasOwn(this.data.grants, grantId)) return false;
    const g = this.data.grants[grantId];
    delete this.data.grants[grantId];
    for (const [h, a] of Object.entries(this.data.access)) if (a.grant === grantId) delete this.data.access[h];
    this.store.save();
    this.logger?.info(`доступ «${g.client_name}» → ${g.resource ?? 'все коннекторы'} ${why}`);
    return true;
  }

  // RFC 7009: токен любого вида отзывает весь доступ. Ответ всегда 200.
  async revoke(req, body) {
    const client = await this.authenticateClient(req, body);
    const h = sha256(String(body.token ?? ''));
    const byAccess = this.data.access[h];
    if (byAccess) {
      const g = this.data.grants[byAccess.grant];
      if (g?.client_id === client.id) this.revokeGrant(byAccess.grant, 'отозван приложением');
      return;
    }
    for (const [grantId, g] of Object.entries(this.data.grants)) {
      if (g.client_id === client.id && g.refresh.some((r) => r.hash === h)) {
        this.revokeGrant(grantId, 'отозван приложением');
        return;
      }
    }
  }

  // Токен доступа из заголовка Authorization → доступ или { error }.
  authenticate(bearer, route) {
    if (typeof bearer !== 'string' || !bearer) return { error: 'missing' };
    const h = sha256(bearer);
    const a = this.data.access[h];
    const t = this.now();
    if (!a || a.expires_at < t) return this.cliToken(h, route) ?? { error: 'invalid' };
    const g = this.data.grants[a.grant];
    if (!g) return { error: 'invalid' };
    if (!this.audienceAllows(g.resource, route)) return { error: 'audience' };
    // Время последнего использования — не чаще раза в минуту, чтобы не писать файл на каждый запрос.
    if (t - g.last_used_at > 60_000) {
      g.last_used_at = t;
      this.store.save();
    }
    return { grantId: a.grant, grant: g };
  }

  // Короткие токены из командной строки (cli.js token) — проверить коннектор без
  // приложения. Файл пишет только администратор сервера.
  cliToken(hash, route) {
    const list = readJson(path.join(this.config.dataDir, 'cli-tokens.json'), {})?.tokens ?? [];
    const hit = list.find((x) => x.hash === hash && x.expires_at > this.now());
    if (!hit) return null;
    if (hit.route && hit.route !== route.path) return { error: 'audience' };
    return { grantId: `cli-${hash.slice(0, 12)}`, grant: { client_name: 'CLI', resource: null } };
  }

  grants() {
    return Object.entries(this.data.grants)
      .map(([id, g]) => ({
        id,
        clientName: g.client_name,
        resourceTitle: this.resourceInfo(g.resource)?.title ?? g.resource,
        created: g.created_at,
        lastUsed: g.last_used_at,
      }))
      .sort((a, b) => b.lastUsed - a.lastUsed);
  }

  // Истёкшие токены и доступы, которыми давно не пользовались.
  prune() {
    const t = this.now();
    let changed = false;
    for (const [h, a] of Object.entries(this.data.access)) {
      if (a.expires_at < t) {
        delete this.data.access[h];
        changed = true;
      }
    }
    for (const [id, g] of Object.entries(this.data.grants)) {
      const live = g.refresh.filter((r) => r.expires_at > t && !(r.used_at && t - r.used_at > REFRESH_GRACE_MS));
      if (live.length !== g.refresh.length) {
        g.refresh = live;
        changed = true;
      }
      const hasAccess = Object.values(this.data.access).some((a) => a.grant === id);
      if (!live.length && !hasAccess) {
        delete this.data.grants[id];
        changed = true;
      }
    }
    if (changed) this.store.save();
  }
}
