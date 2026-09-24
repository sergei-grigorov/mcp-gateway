import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { test } from 'node:test';

import { loadConfig } from '../server/config.js';
import { hashPassword, Throttle, verifyPassword } from '../server/owner.js';
import { authorizeAndToken, fakeUpstream, form, PASSWORD, req, SECRET, startGateway } from './helpers.js';

const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

async function signIn(base, password = PASSWORD) {
  const r = await req(base, '/signin', { method: 'POST', headers: { ...form({}).headers, Origin: base }, body: new URLSearchParams({ password, next: '/' }).toString() });
  const cookie = r.headers.get('set-cookie')?.split(';')[0];
  return { r, cookie };
}

test('настройки шлюза из окружения', () => {
  const routes = JSON.stringify([{ path: '/bybit/', title: 'Bybit', upstream: 'http://bybit:8080', public: ['alerts'] }]);
  const c = loadConfig({ PUBLIC_URL: 'https://Agent.Example.com', ROUTES: routes, GATEWAY_SECRET: SECRET, DATA_DIR: '/tmp/x' });
  assert.equal(c.origin, 'https://agent.example.com');
  assert.equal(c.https, true);
  assert.deepEqual(c.routes, [{ path: '/bybit', title: 'Bybit', upstream: 'http://bybit:8080', public: ['/alerts'] }]);
  assert.equal(c.listen.port, 48678);
  assert.equal(c.trustProxy, true);
  assert.throws(() => loadConfig({ PUBLIC_URL: 'https://a.example/x', ROUTES: routes, GATEWAY_SECRET: SECRET }), /без пути/);
  assert.throws(() => loadConfig({ PUBLIC_URL: 'https://a.example', ROUTES: routes, GATEWAY_SECRET: 'short' }), /GATEWAY_SECRET/);
  assert.throws(() => loadConfig({ PUBLIC_URL: 'https://a.example', ROUTES: JSON.stringify([{ path: '/token', upstream: 'http://x:1' }]), GATEWAY_SECRET: SECRET }), /занят/);
  assert.throws(() => loadConfig({ PUBLIC_URL: 'https://a.example', ROUTES: JSON.stringify([{ path: '/x', upstream: 'http://x:1', public: ['/settings'] }]), GATEWAY_SECRET: SECRET }), /без входа/);
});

test('пароль владельца: scrypt и защита от подбора', async () => {
  const rec = await hashPassword('correct horse battery');
  assert.equal(rec.algo, 'scrypt');
  assert.ok(await verifyPassword('correct horse battery', rec));
  assert.ok(!(await verifyPassword('correct horse batterY', rec)));
  let t = 0;
  const th = new Throttle({ perIp: 3, global: 5, windowMs: 1000, now: () => t });
  for (let i = 0; i < 3; i++) th.fail('a');
  assert.ok(th.retryAfter('a') > 0);
  assert.equal(th.retryAfter('b'), 0);
  th.fail('b');
  th.fail('c');
  assert.ok(th.retryAfter('d') > 0, 'общий лимит');
  t = 2000;
  assert.equal(th.retryAfter('a'), 0);
});

test('вход владельца: пароль, cookie, выход; страницы коннекторов только после входа', async () => {
  const up = await fakeUpstream(() => ({ status: 200, headers: { 'Content-Type': 'text/html' }, body: '<p>settings</p>' }));
  const g = await startGateway({ upstream: up.url });
  try {
    const anon = await req(g.base, '/bybit/settings');
    assert.equal(anon.status, 303);
    assert.equal(anon.headers.get('location'), '/signin?next=%2Fbybit%2Fsettings');
    assert.equal((await req(g.base, '/bybit/settings', { method: 'POST', body: 'x=1' })).status, 401);
    assert.equal(up.seen.length, 0, 'коннектор не видел запросов без входа');

    const wrong = await signIn(g.base, 'wrong-password-1');
    assert.equal(wrong.r.status, 401);
    const cross = await req(g.base, '/signin', { method: 'POST', headers: { ...form({}).headers, Origin: 'https://evil.example' }, body: `password=${PASSWORD}` });
    assert.equal(cross.status, 403);
    const { r, cookie } = await signIn(g.base);
    assert.equal(r.status, 303);
    assert.match(r.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);

    const page = await req(g.base, '/bybit/settings', { headers: { Cookie: cookie, Authorization: 'Bearer should-not-pass' } });
    assert.equal(page.status, 200);
    const seen = up.seen.at(-1);
    assert.equal(seen.headers['x-gateway-auth'], 'owner');
    assert.equal(seen.headers['x-gateway-secret'], SECRET);
    assert.equal(seen.headers.cookie, undefined, 'cookie шлюза коннектору не передаётся');
    assert.equal(seen.headers.authorization, undefined);
    // Изменение с чужой страницы — отказ до коннектора.
    const before = up.seen.length;
    assert.equal((await req(g.base, '/bybit/settings', { method: 'POST', headers: { Cookie: cookie, Origin: 'https://evil.example' }, body: 'x=1' })).status, 403);
    assert.equal(up.seen.length, before);
    // Подделанные заголовки шлюза от клиента не доходят.
    await req(g.base, '/bybit/settings', { headers: { Cookie: cookie, 'X-Gateway-Auth': 'token', 'X-Gateway-Grant': 'forged' } });
    assert.equal(up.seen.at(-1).headers['x-gateway-auth'], 'owner');
    assert.equal(up.seen.at(-1).headers['x-gateway-grant'], undefined);

    const home = await req(g.base, '/', { headers: { Cookie: cookie } });
    assert.match(home.text, /Подключённые приложения/);
    const out = await req(g.base, '/signout', { method: 'POST', headers: { Cookie: cookie, Origin: g.base } });
    assert.equal(out.status, 303);
    assert.equal((await req(g.base, '/bybit/settings', { headers: { Cookie: cookie } })).status, 303);
  } finally {
    await g.close();
    await up.close();
  }
});

test('MCP через шлюз: токен проверен, коннектор получает доступ и поток SSE без задержек', async () => {
  const up = await fakeUpstream((request, body, res) => {
    if (request.headers.accept === 'text/event-stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'X-Accel-Buffering': 'no' });
      res.write('data: {"n":1}\n\n');
      setTimeout(() => {
        res.write('data: {"n":2}\n\n');
        res.end();
      }, 150);
      return null;
    }
    return { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ echo: body }) };
  });
  const g = await startGateway({ upstream: up.url });
  try {
    const t = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    const auth = { Authorization: `Bearer ${t.token.json.access_token}`, 'Content-Type': 'application/json' };
    const r = await req(g.base, '/bybit', { method: 'POST', headers: auth, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
    assert.equal(r.status, 200);
    assert.equal(r.json.echo, '{"jsonrpc":"2.0","id":1,"method":"ping"}');
    const seen = up.seen.at(-1);
    assert.equal(seen.url, '/bybit');
    assert.equal(seen.headers['x-gateway-auth'], 'token');
    assert.equal(seen.headers['x-gateway-grant'], g.gw.oauth.grants()[0].id);
    assert.equal(seen.headers.authorization, undefined, 'токен OAuth коннектору не передаётся');
    assert.equal(seen.headers.host, g.config.host);

    const started = Date.now();
    const res = await fetch(`${g.base}/bybit/mcp`, { method: 'POST', headers: { ...auth, Accept: 'text/event-stream' }, body: '{}' });
    const reader = res.body.getReader();
    const first = new TextDecoder().decode((await reader.read()).value);
    assert.match(first, /"n":1/);
    assert.ok(Date.now() - started < 140, 'первое событие пришло до конца ответа');
    let rest = '';
    for (let c = await reader.read(); !c.done; c = await reader.read()) rest += new TextDecoder().decode(c.value);
    assert.match(rest, /"n":2/);
  } finally {
    await g.close();
    await up.close();
  }
});

test('WebSocket — только на открытые пути коннектора; коннектор недоступен — 502', async () => {
  const up = await fakeUpstream(() => ({ status: 404, body: 'no' }));
  up.server.on('upgrade', (request, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Seen-Auth: ' + request.headers['x-gateway-auth'] + '\r\n\r\n');
    socket.on('data', (d) => socket.write(d));
    socket.on('end', () => socket.end());
  });
  const g = await startGateway({ upstream: up.url });
  const upgrade = (p) =>
    new Promise((resolve, reject) => {
      const s = net.connect(Number(new URL(g.base).port), '127.0.0.1', () => {
        s.write(`GET ${p} HTTP/1.1\r\nHost: ${g.config.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`);
      });
      let buf = '';
      s.on('data', (d) => {
        buf += d.toString();
        if (buf.includes('\r\n\r\n')) {
          if (buf.startsWith('HTTP/1.1 101')) {
            s.write('ping!');
            if (!buf.includes('ping!')) return;
          }
          s.destroy();
          resolve(buf);
        }
      });
      s.on('error', reject);
    });
  try {
    const ok = await upgrade('/bybit/alerts/abcdefghijklmnopqrstuv');
    assert.match(ok, /^HTTP\/1.1 101/);
    assert.match(ok, /X-Seen-Auth: none/);
    assert.match(ok, /ping!/, 'байты идут в обе стороны');
    assert.match(await upgrade('/bybit/settings'), /^HTTP\/1.1 404/);
    assert.match(await upgrade('/bybit'), /^HTTP\/1.1 404/);
  } finally {
    await g.close();
    await up.close();
  }
  const down = await startGateway({ upstream: 'http://127.0.0.1:9' });
  try {
    const { cookie } = await signIn(down.base);
    assert.equal((await req(down.base, '/bybit/settings', { headers: { Cookie: cookie } })).status, 502);
  } finally {
    await down.close();
  }
});

// fetch не даёт подменить Host — запрос через http.request.
function rawStatus(base, pathname, headers) {
  return new Promise((resolve, reject) => {
    const u = new URL(base);
    const r = http.request({ host: u.hostname, port: u.port, path: pathname, headers }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    r.on('error', reject);
    r.end();
  });
}

test('чужой Host — 421; за прокси http перенаправляется на https', async () => {
  const g = await startGateway();
  try {
    assert.equal(await rawStatus(g.base, '/', { Host: 'evil.example' }), 421);
    assert.equal(await rawStatus(g.base, '/', { Host: g.config.host }), 200);
  } finally {
    await g.close();
  }
  const h = await startGateway({ config: { trustProxy: true } });
  h.config.https = true;
  try {
    const r = await req(h.base, '/signin', { headers: { 'X-Forwarded-Proto': 'http' } });
    assert.equal(r.status, 308);
    assert.equal(r.headers.get('location'), `${h.base}/signin`);
    assert.equal((await req(h.base, '/token', { method: 'POST', headers: { 'X-Forwarded-Proto': 'http' } })).status, 403);
    assert.equal((await req(h.base, '/.well-known/oauth-authorization-server', { headers: { 'X-Forwarded-Proto': 'https' } })).status, 200);
  } finally {
    await h.close();
  }
});

test('смена пароля владельца и отзыв доступа с главной страницы', async () => {
  const g = await startGateway();
  try {
    await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    const { cookie } = await signIn(g.base);
    const post = (p, body, c = cookie) => req(g.base, p, { method: 'POST', headers: { ...form({}).headers, Cookie: c, Origin: g.base }, body: new URLSearchParams(body).toString() });
    assert.equal((await post('/password', { current: 'wrong', password: 'new-password-456', confirm: 'new-password-456' })).headers.get('location'), '/?error=password');
    assert.equal((await post('/password', { current: PASSWORD, password: 'short', confirm: 'short' })).headers.get('location'), '/?error=short');
    const changed = await post('/password', { current: PASSWORD, password: 'new-password-456', confirm: 'new-password-456' });
    assert.equal(changed.headers.get('location'), '/?done=password');
    const fresh = changed.headers.get('set-cookie').split(';')[0];
    assert.equal((await signIn(g.base, PASSWORD)).r.status, 401);
    assert.equal((await signIn(g.base, 'new-password-456')).r.status, 303);
    const grant = g.gw.oauth.grants()[0].id;
    assert.equal((await post('/grants/revoke', { grant }, fresh)).headers.get('location'), '/?done=revoked');
    assert.equal(g.gw.oauth.grants().length, 0);
  } finally {
    await g.close();
  }
});

test('формы со своих страниц: браузер может прислать Origin: null — тогда решает Sec-Fetch-Site', async () => {
  const g = await startGateway();
  try {
    const page = await req(g.base, '/signin');
    // С no-referrer браузер отправил бы форму с Origin: null — политика должна быть same-origin.
    assert.equal(page.headers.get('referrer-policy'), 'same-origin');
    assert.match(page.text, /<meta name="referrer" content="same-origin">/);
    const body = new URLSearchParams({ password: PASSWORD, next: '/' }).toString();
    const post = (headers) => req(g.base, '/signin', { method: 'POST', headers: { ...form({}).headers, ...headers }, body });
    assert.equal((await post({ Origin: 'null', 'Sec-Fetch-Site': 'same-origin' })).status, 303);
    assert.equal((await post({ Origin: 'null' })).status, 403);
    assert.equal((await post({ Origin: 'null', 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post({ 'Sec-Fetch-Site': 'same-origin' })).status, 303);
  } finally {
    await g.close();
  }
});

// Сырой запрос к шлюзу по сокету: ответ целиком (до закрытия соединения).
function rawRequest(base, text) {
  return new Promise((resolve, reject) => {
    const s = net.connect(Number(new URL(base).port), '127.0.0.1', () => s.write(text));
    let buf = '';
    s.on('data', (d) => (buf += d.toString('latin1')));
    s.on('end', () => resolve(buf));
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      resolve(buf);
    }, 1500);
  });
}

test('прокси: тело без разметки не протащит второй запрос к коннектору', async () => {
  const up = await fakeUpstream((request, body) => ({ status: 200, body: `${request.method} ${request.url} [${body}]` }));
  const g = await startGateway({ upstream: up.url });
  try {
    const smuggled = 'GET /bybit/settings HTTP/1.1\r\nHost: x\r\nX-Gateway-Auth: owner\r\n\r\n';
    const chunk = `${smuggled.length.toString(16)}\r\n${smuggled}\r\n0\r\n\r\n`;
    // GET с телом частями — отказ, коннектор ничего не получает.
    const get = await rawRequest(g.base, `GET /bybit/alerts/x HTTP/1.1\r\nHost: ${g.config.host}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk}`);
    assert.match(get, /^HTTP\/1.1 400/);
    assert.equal(up.seen.length, 0);
    // POST с телом частями — один запрос к коннектору, тело размечено и доходит целиком.
    const post = await rawRequest(g.base, `POST /bybit/alerts/x HTTP/1.1\r\nHost: ${g.config.host}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk}`);
    assert.match(post, /^HTTP\/1.1 200/);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(up.seen.length, 1, 'ровно один запрос');
    assert.equal(up.seen[0].headers['transfer-encoding'], 'chunked');
    assert.equal(up.seen[0].body, smuggled);
    // Путь уходит нормализованным.
    await req(g.base, '/bybit/alerts/a/../b?x=1');
    assert.equal(up.seen.at(-1).url, '/bybit/alerts/b?x=1');
  } finally {
    await g.close();
    await up.close();
  }
});

test('вход: next не уводит на чужой сайт; искажённые запросы — 4xx, а не 500', async () => {
  const g = await startGateway();
  try {
    for (const bad of ['/%09/evil.example/x', '/%0a/evil.example', '/\\evil.example', '//evil.example', 'https://evil.example']) {
      const page = await req(g.base, `/signin?next=${encodeURIComponent(decodeURIComponent(bad))}`);
      assert.match(page.text, /name="next" value="\/"/, bad);
    }
    const good = await req(g.base, `/signin?next=${encodeURIComponent('/bybit/settings?saved=1')}`);
    assert.match(good.text, /name="next" value="\/bybit\/settings\?saved=1"/);
    const post = await req(g.base, '/signin', { method: 'POST', headers: { ...form({}).headers, Origin: g.base }, body: new URLSearchParams({ password: PASSWORD, next: '/\t/evil.example/phish' }).toString() });
    assert.equal(post.status, 303);
    assert.equal(post.headers.get('location'), '/');

    const json = (p, body) => req(g.base, p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
    for (const body of ['null', '123', '"x"', '[]']) {
      const t = await json('/token', body);
      assert.equal(t.status, 400, `/token ${body}`);
      assert.equal(t.json.error, 'invalid_request');
      assert.equal((await json('/revoke', body)).status, 400, `/revoke ${body}`);
    }
    for (const id of ['__proto__', 'constructor', 'toString']) {
      const r = await req(g.base, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: id, redirect_uri: 'https://claude.ai/api/mcp/auth_callback' })}`);
      assert.equal(r.status, 400, id);
    }
    const basic = await req(g.base, '/token', {
      method: 'POST',
      headers: { ...form({}).headers, Authorization: `Basic ${Buffer.from('%E0%A4%A:x').toString('base64')}` },
      body: 'grant_type=refresh_token&refresh_token=x',
    });
    assert.equal(basic.status, 401);
    assert.equal(basic.json.error, 'invalid_client');
    assert.equal(g.gw.oauth.revokeGrant('__proto__'), false);
  } finally {
    await g.close();
  }
});
