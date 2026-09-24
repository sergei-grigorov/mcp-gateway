// Настройки шлюза — переменные окружения.
//
//   PUBLIC_URL        адрес шлюза в интернете: https://agent.example.com (без пути)
//   ROUTES            коннекторы: JSON-массив [{ "path": "/bybit", "title": "Bybit",
//                     "upstream": "http://bybit:8080", "public": ["/alerts"] }] или
//                     ROUTES_FILE — файл с ним. public — пути коннектора, доступные без
//                     входа (адреса WebSocket с токеном внутри: их проверяет коннектор).
//   GATEWAY_SECRET    общий секрет с коннекторами (или GATEWAY_SECRET_FILE), ≥ 32 символов
//   DATA_DIR          папка данных: owner.json (пароль владельца), oauth.json (доступы)
//   HOST, PORT        где слушать (по умолчанию 127.0.0.1:48678)
//   TRUST_PROXY       1 (по умолчанию) — шлюз стоит за обратным прокси (Nginx Proxy
//                     Manager): схема из X-Forwarded-Proto, адрес клиента из X-Real-IP
//   REDIRECT_URIS     дополнительные разрешённые адреса возврата OAuth (через пробел)
//   ACCESS_TOKEN_TTL  срок токена доступа, секунды (по умолчанию сутки)
//   REFRESH_TOKEN_TTL срок токена обновления, секунды (по умолчанию 90 дней)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function readFileVar(env, name) {
  if (env[name]) return String(env[name]).trim();
  const file = env[`${name}_FILE`];
  if (!file) return '';
  return fs.readFileSync(file, 'utf8').trim();
}

function int(env, name, fallback, min, max) {
  const s = String(env[name] ?? '').trim();
  if (!s) return fallback;
  const n = Number(s);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name}: нужно целое число от ${min} до ${max}`);
  return n;
}

export function normalizeRoutes(list) {
  if (!Array.isArray(list) || !list.length) throw new Error('ROUTES: нужен непустой массив коннекторов');
  const seen = new Set();
  return list.map((r, i) => {
    const where = `ROUTES[${i}]`;
    const p = String(r?.path ?? '').replace(/\/+$/, '');
    if (!/^\/[a-z0-9][a-z0-9_-]*$/i.test(p)) throw new Error(`${where}.path: нужен путь вида /bybit`);
    if (['/.well-known', '/authorize', '/token', '/register', '/revoke', '/signin', '/signout', '/password', '/grants'].includes(p.toLowerCase())) {
      throw new Error(`${where}.path: ${p} занят самим шлюзом`);
    }
    if (seen.has(p.toLowerCase())) throw new Error(`${where}.path: ${p} повторяется`);
    seen.add(p.toLowerCase());
    let upstream;
    try {
      upstream = new URL(String(r.upstream));
    } catch {
      throw new Error(`${where}.upstream: нужен адрес вида http://host:port`);
    }
    if (upstream.protocol !== 'http:' || upstream.pathname !== '/' || upstream.search) {
      throw new Error(`${where}.upstream: нужен адрес вида http://host:port без пути`);
    }
    const pub = (r.public ?? []).map((x) => `/${String(x).replace(/^\/+|\/+$/g, '')}`);
    for (const x of pub) {
      if (x === '/' || x === '/mcp' || x === '/settings') throw new Error(`${where}.public: ${x} нельзя открывать без входа`);
    }
    return { path: p, title: String(r.title ?? p.slice(1)), upstream: upstream.origin, public: pub };
  });
}

export function loadConfig(env = process.env) {
  const publicRaw = String(env.PUBLIC_URL ?? '').trim();
  let publicUrl;
  try {
    publicUrl = new URL(publicRaw);
  } catch {
    throw new Error('PUBLIC_URL: нужен адрес шлюза, например https://agent.example.com');
  }
  if (!['https:', 'http:'].includes(publicUrl.protocol) || (publicUrl.pathname !== '/' && publicUrl.pathname !== '')) {
    throw new Error('PUBLIC_URL: нужен адрес без пути, например https://agent.example.com');
  }
  const routesText = readFileVar(env, 'ROUTES');
  if (!routesText) throw new Error('ROUTES: не заданы коннекторы');
  let routes;
  try {
    routes = JSON.parse(routesText);
  } catch {
    throw new Error('ROUTES: не удалось разобрать JSON');
  }
  const secret = readFileVar(env, 'GATEWAY_SECRET');
  if (secret.length < 32) throw new Error('GATEWAY_SECRET: нужен секрет не короче 32 символов');
  const redirectUris = String(env.REDIRECT_URIS ?? '')
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((u) => {
      try {
        return new URL(u).href;
      } catch {
        throw new Error(`REDIRECT_URIS: «${u}» — не адрес`);
      }
    });
  return {
    origin: publicUrl.origin,
    host: publicUrl.host.toLowerCase(),
    https: publicUrl.protocol === 'https:',
    siteName: String(env.SITE_NAME ?? '').trim() || publicUrl.host,
    routes: normalizeRoutes(routes),
    secret,
    dataDir: path.resolve(String(env.DATA_DIR ?? '').trim() || path.join(os.homedir(), '.mcp-gateway')),
    listen: { host: String(env.HOST ?? '').trim() || '127.0.0.1', port: int(env, 'PORT', 48678, 1, 65535) },
    trustProxy: !/^(0|false|no|off)$/i.test(String(env.TRUST_PROXY ?? '1').trim()),
    redirectUris,
    accessTtlSec: int(env, 'ACCESS_TOKEN_TTL', 86_400, 300, 30 * 86_400),
    refreshTtlSec: int(env, 'REFRESH_TOKEN_TTL', 90 * 86_400, 3600, 365 * 86_400),
  };
}
