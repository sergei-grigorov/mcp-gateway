// Общие заготовки тестов шлюза: временная папка, настройки, поддельный коннектор,
// HTTP-запросы и прохождение OAuth «как владелец в браузере».

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { Gateway } from '../server/app.js';
import { normalizeRoutes } from '../server/config.js';

export const silentLogger = { info() {}, warn() {}, error() {} };
export const SECRET = 'x'.repeat(40);
export const PASSWORD = 'owner-password-123';

export function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'gw-test-'));
}

export function makeConfig(overrides = {}) {
  return {
    origin: 'http://127.0.0.1:1',
    host: '127.0.0.1:1',
    https: false,
    siteName: 'test',
    routes: normalizeRoutes([
      { path: '/bybit', title: 'Bybit', upstream: 'http://127.0.0.1:9', public: ['/alerts'] },
      { path: '/telegram', title: 'Telegram', upstream: 'http://127.0.0.1:9', public: ['/messages'] },
    ]),
    secret: SECRET,
    dataDir: tempDir(),
    listen: { host: '127.0.0.1', port: 0 },
    trustProxy: false,
    redirectUris: [],
    accessTtlSec: 3600,
    refreshTtlSec: 86_400,
    ...overrides,
  };
}

// Поддельный коннектор: запоминает запросы и отвечает по handler(req, body) → { status, headers, body }.
export async function fakeUpstream(handler = () => ({ status: 200, body: 'ok' })) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const body = Buffer.concat(chunks).toString('utf8');
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const out = await handler(req, body, res);
      if (out === null) return; // ответ пишет сам handler
      res.writeHead(out.status ?? 200, out.headers ?? { 'Content-Type': 'text/plain' });
      res.end(out.body ?? '');
    });
  });
  const sockets = new Set();
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const close = () => {
    for (const s of sockets) s.destroy();
    return new Promise((r) => server.close(r));
  };
  return { server, seen, url: `http://127.0.0.1:${server.address().port}`, close };
}

// Шлюз на случайном порту; upstream — адрес поддельного коннектора для обоих путей.
export async function startGateway({ upstream = 'http://127.0.0.1:9', config: extra = {}, fetchMetadata } = {}) {
  const config = makeConfig(extra);
  config.routes = normalizeRoutes([
    { path: '/bybit', title: 'Bybit', upstream, public: ['/alerts'] },
    { path: '/telegram', title: 'Telegram', upstream, public: ['/messages'] },
  ]);
  const gw = new Gateway({ config, logger: silentLogger, fetchMetadata });
  await gw.owner.setPassword(PASSWORD);
  config.listen = { host: '127.0.0.1', port: 0 };
  const addr = await gw.listen();
  // Адрес шлюза становится известен после запуска — подставляем его как публичный.
  config.origin = `http://127.0.0.1:${addr.port}`;
  config.host = `127.0.0.1:${addr.port}`;
  return { gw, config, base: config.origin, close: () => gw.close() };
}

export async function req(base, pathname, { method = 'GET', headers = {}, body, redirect = 'manual' } = {}) {
  const res = await fetch(new URL(pathname, base), { method, headers, body, redirect });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // не JSON
  }
  return { status: res.status, headers: res.headers, text, json };
}

export const form = (obj) => ({
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(obj).toString(),
});

export function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// Полный вход: /authorize → страница разрешения → «Разрешить» с паролем → код → /token.
export async function authorizeAndToken(base, { clientId, redirectUri, resource, password = PASSWORD, secret } = {}) {
  const { verifier, challenge } = pkce();
  const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256', state: 'st1' });
  if (resource) q.set('resource', resource);
  const page = await req(base, `/authorize?${q}`);
  const id = /name="request" value="([^"]+)"/.exec(page.text)?.[1];
  if (!id) return { page };
  // Форма отправляется туда, куда указывает сама страница, — как в браузере.
  const action = /<form method="post" action="([^"]+)">/.exec(page.text)?.[1];
  if (action !== '/authorize') throw new Error(`consent form posts to ${action}`);
  const allow = await req(base, action, { method: 'POST', ...form({ request: id, password, decision: 'allow' }), headers: { ...form({}).headers, Origin: base } });
  const location = allow.headers.get('location');
  if (allow.status !== 302 || !location) return { page, allow };
  const back = new URL(location);
  const tokenBody = { grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: redirectUri, code_verifier: verifier, client_id: clientId };
  if (resource) tokenBody.resource = resource;
  if (secret) tokenBody.client_secret = secret;
  const token = await req(base, '/token', { method: 'POST', ...form(tokenBody) });
  return { page, allow, back, token, verifier };
}
