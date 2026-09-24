import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalResource, redirectMatches } from '../server/oauth.js';
import { authorizeAndToken, form, PASSWORD, pkce, req, startGateway } from './helpers.js';

const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

test('канонический вид ресурса и совпадение адресов возврата', () => {
  assert.equal(canonicalResource('HTTPS://Agent.Example.com:443/bybit/'), 'https://agent.example.com/bybit');
  assert.equal(canonicalResource('https://agent.example.com/'), 'https://agent.example.com');
  assert.equal(canonicalResource('https://agent.example.com/x#frag'), null);
  assert.equal(canonicalResource('https://agent.example.com/x?q=1'), null);
  assert.equal(canonicalResource('ftp://agent.example.com/x'), null);
  // loopback — любой порт (RFC 8252), остальное — буква в букву
  assert.ok(redirectMatches('http://localhost/callback', 'http://localhost:53682/callback'));
  assert.ok(!redirectMatches('http://localhost/callback', 'http://127.0.0.1:53682/callback'));
  assert.ok(!redirectMatches('http://localhost/callback', 'http://localhost:1/other'));
  assert.ok(redirectMatches(CALLBACK, CALLBACK));
  assert.ok(!redirectMatches(CALLBACK, `${CALLBACK}?x=1`));
  assert.ok(!redirectMatches(CALLBACK, 'https://claude.ai.evil.com/api/mcp/auth_callback'));
});

test('метаданные: сервер авторизации в корне, ресурсы по путям и корень', async () => {
  const g = await startGateway();
  try {
    const as = await req(g.base, '/.well-known/oauth-authorization-server');
    assert.equal(as.status, 200);
    assert.equal(as.json.issuer, g.base);
    assert.equal(as.json.authorization_endpoint, `${g.base}/authorize`);
    assert.equal(as.json.token_endpoint, `${g.base}/token`);
    assert.equal(as.json.registration_endpoint, `${g.base}/register`);
    assert.deepEqual(as.json.code_challenge_methods_supported, ['S256']);
    assert.ok(as.json.token_endpoint_auth_methods_supported.includes('none'));
    assert.equal(as.json.client_id_metadata_document_supported, true);
    assert.equal(as.json.authorization_response_iss_parameter_supported, true);
    assert.deepEqual((await req(g.base, '/.well-known/openid-configuration')).json, as.json);

    const prm = await req(g.base, '/.well-known/oauth-protected-resource/bybit');
    assert.deepEqual(prm.json.authorization_servers, [g.base]);
    assert.equal(prm.json.resource, `${g.base}/bybit`);
    assert.equal((await req(g.base, '/.well-known/oauth-protected-resource/bybit/mcp')).json.resource, `${g.base}/bybit/mcp`);
    assert.equal((await req(g.base, '/.well-known/oauth-protected-resource/telegram')).json.resource_name, 'Telegram');
    // Корневой документ описывает весь домен тем же сервером авторизации.
    const root = await req(g.base, '/.well-known/oauth-protected-resource');
    assert.equal(root.json.resource, g.base);
    assert.equal((await req(g.base, '/.well-known/oauth-protected-resource/unknown')).status, 404);
    assert.equal((await req(g.base, '/.well-known/oauth-protected-resource/bybit/settings')).status, 404);
  } finally {
    await g.close();
  }
});

test('MCP без токена: 401 со ссылкой на метаданные ресурса того пути, что запрошен', async () => {
  const g = await startGateway();
  try {
    for (const p of ['/bybit', '/bybit/mcp', '/telegram']) {
      const r = await req(g.base, p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      assert.equal(r.status, 401);
      assert.equal(r.headers.get('www-authenticate'), `Bearer resource_metadata="${g.base}/.well-known/oauth-protected-resource${p}"`);
    }
    const bad = await req(g.base, '/bybit', { method: 'POST', headers: { Authorization: 'Bearer nope', 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(bad.status, 401);
    assert.match(bad.headers.get('www-authenticate'), /error="invalid_token"/);
  } finally {
    await g.close();
  }
});

test('CIMD: Claude и Claude Code — встроенные документы, свой адрес возврата у каждого', async () => {
  const g = await startGateway({ fetchMetadata: async () => assert.fail('встроенные документы не скачиваются') });
  try {
    const web = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    assert.equal(web.token.status, 200);
    assert.equal(web.back.searchParams.get('iss'), g.base);
    assert.equal(web.back.searchParams.get('state'), 'st1');
    assert.match(web.page.text, /Claude/);
    assert.equal(web.token.json.token_type, 'Bearer');
    assert.ok(web.token.json.refresh_token);

    const code = await authorizeAndToken(g.base, { clientId: CLAUDE_CODE, redirectUri: 'http://localhost:40123/callback', resource: `${g.base}/telegram` });
    assert.equal(code.token.status, 200);

    // Чужой адрес возврата у Claude — страница с ошибкой, без перенаправления.
    const evil = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: 'https://evil.example/cb' });
    assert.equal(evil.page.status, 400);
    assert.equal(evil.page.headers.get('location'), null);
  } finally {
    await g.close();
  }
});

test('CIMD: чужой документ скачивается и проверяется', async () => {
  const docs = {
    'https://good.example/client.json': { client_id: 'https://good.example/client.json', client_name: 'Good', redirect_uris: ['http://127.0.0.1/cb'] },
    'https://mismatch.example/c.json': { client_id: 'https://other.example/c.json', client_name: 'X', redirect_uris: ['http://127.0.0.1/cb'] },
    'https://secret.example/c.json': { client_id: 'https://secret.example/c.json', client_name: 'X', redirect_uris: ['http://127.0.0.1/cb'], token_endpoint_auth_method: 'client_secret_post' },
  };
  const g = await startGateway({ fetchMetadata: async (url) => docs[url] ?? Promise.reject(new Error('HTTP 404')) });
  try {
    const good = await authorizeAndToken(g.base, { clientId: 'https://good.example/client.json', redirectUri: 'http://127.0.0.1:5555/cb' });
    assert.equal(good.token.status, 200);
    for (const id of ['https://mismatch.example/c.json', 'https://secret.example/c.json', 'https://missing.example/c.json', 'https://good.example/']) {
      const r = await authorizeAndToken(g.base, { clientId: id, redirectUri: 'http://127.0.0.1:5555/cb' });
      assert.equal(r.page.status, 400, id);
    }
  } finally {
    await g.close();
  }
});

test('динамическая регистрация: только разрешённые адреса возврата, секрет для client_secret_post', async () => {
  const g = await startGateway();
  try {
    const reg = (body) => req(g.base, '/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const bad = await reg({ redirect_uris: ['https://evil.example/cb'], token_endpoint_auth_method: 'none' });
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error, 'invalid_redirect_uri');
    assert.equal((await reg({ redirect_uris: [] })).status, 400);
    assert.equal((await reg({ redirect_uris: [CALLBACK], token_endpoint_auth_method: 'private_key_jwt' })).json.error, 'invalid_client_metadata');

    // Так регистрируется облачный Claude (client_secret_post).
    const claude = await reg({ client_name: 'Claude', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'client_secret_post', grant_types: ['authorization_code', 'refresh_token'] });
    assert.equal(claude.status, 201);
    assert.ok(claude.json.client_secret);
    assert.equal(claude.json.token_endpoint_auth_method, 'client_secret_post');
    const ok = await authorizeAndToken(g.base, { clientId: claude.json.client_id, redirectUri: CALLBACK, resource: `${g.base}/bybit`, secret: claude.json.client_secret });
    assert.equal(ok.token.status, 200);
    const wrong = await authorizeAndToken(g.base, { clientId: claude.json.client_id, redirectUri: CALLBACK, secret: 'wrong' });
    assert.equal(wrong.token.status, 401);
    assert.equal(wrong.token.json.error, 'invalid_client');

    // Публичный клиент с loopback (Claude Code, MCP Inspector).
    const local = await reg({ client_name: 'Local', redirect_uris: ['http://localhost:3118/callback'], token_endpoint_auth_method: 'none' });
    assert.equal(local.status, 201);
    assert.equal(local.json.client_secret, undefined);
    assert.equal((await authorizeAndToken(g.base, { clientId: local.json.client_id, redirectUri: 'http://localhost:9999/callback' })).token.status, 200);
  } finally {
    await g.close();
  }
});

test('авторизация: PKCE обязателен, ошибки уходят приложению, неверный пароль не выдаёт код', async () => {
  const g = await startGateway();
  try {
    const base = { client_id: CLAUDE, redirect_uri: CALLBACK, state: 's' };
    const noPkce = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'code' })}`);
    assert.equal(noPkce.status, 302);
    assert.equal(new URL(noPkce.headers.get('location')).searchParams.get('error'), 'invalid_request');
    const { challenge } = pkce();
    const plain = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'code', code_challenge: challenge, code_challenge_method: 'plain' })}`);
    assert.equal(new URL(plain.headers.get('location')).searchParams.get('error'), 'invalid_request');
    const token = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'token', code_challenge: challenge, code_challenge_method: 'S256' })}`);
    assert.equal(new URL(token.headers.get('location')).searchParams.get('error'), 'unsupported_response_type');
    const target = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', resource: 'https://evil.example/mcp' })}`);
    assert.equal(new URL(target.headers.get('location')).searchParams.get('error'), 'invalid_target');

    const wrong = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, password: 'not-the-password' });
    assert.equal(wrong.allow.status, 401);
    assert.match(wrong.allow.text, /Неверный пароль/);

    // Отказ владельца: access_denied приложению.
    const page = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256' })}`);
    const id = /name="request" value="([^"]+)"/.exec(page.text)[1];
    const deny = await req(g.base, '/authorize', { method: 'POST', headers: { ...form({}).headers, Origin: g.base }, body: new URLSearchParams({ request: id, decision: 'deny' }).toString() });
    assert.equal(new URL(deny.headers.get('location')).searchParams.get('error'), 'access_denied');
    // Отправка формы с чужой страницы не принимается.
    const page2 = await req(g.base, `/authorize?${new URLSearchParams({ ...base, response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256' })}`);
    const id2 = /name="request" value="([^"]+)"/.exec(page2.text)[1];
    const csrf = await req(g.base, '/authorize', { method: 'POST', headers: { ...form({}).headers, Origin: 'https://evil.example' }, body: new URLSearchParams({ request: id2, password: PASSWORD, decision: 'allow' }).toString() });
    assert.equal(csrf.status, 403);
  } finally {
    await g.close();
  }
});

test('токены: код одноразовый, PKCE и ресурс сверяются, повтор кода отзывает доступ', async () => {
  const g = await startGateway();
  try {
    const first = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    assert.equal(first.token.status, 200);
    const again = await req(g.base, '/token', {
      method: 'POST',
      ...form({ grant_type: 'authorization_code', code: first.back.searchParams.get('code'), redirect_uri: CALLBACK, code_verifier: first.verifier, client_id: CLAUDE }),
    });
    assert.equal(again.json.error, 'invalid_grant');
    // Доступ, выданный по коду, после повтора отозван.
    const mcp = await req(g.base, '/bybit', { method: 'POST', headers: { Authorization: `Bearer ${first.token.json.access_token}`, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(mcp.status, 401);

    // Неверный code_verifier.
    const { challenge } = pkce();
    const q = new URLSearchParams({ response_type: 'code', client_id: CLAUDE, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' });
    const page = await req(g.base, `/authorize?${q}`);
    const id = /name="request" value="([^"]+)"/.exec(page.text)[1];
    const allow = await req(g.base, '/authorize', { method: 'POST', headers: { ...form({}).headers, Origin: g.base }, body: new URLSearchParams({ request: id, password: PASSWORD, decision: 'allow' }).toString() });
    const code = new URL(allow.headers.get('location')).searchParams.get('code');
    const badVerifier = await req(g.base, '/token', { method: 'POST', ...form({ grant_type: 'authorization_code', code, redirect_uri: CALLBACK, code_verifier: 'a'.repeat(50), client_id: CLAUDE }) });
    assert.equal(badVerifier.json.error, 'invalid_grant');

    // Ресурс в запросе токена не совпадает с разрешённым.
    const other = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    const again2 = await req(g.base, '/token', {
      method: 'POST',
      ...form({ grant_type: 'refresh_token', refresh_token: other.token.json.refresh_token, client_id: CLAUDE, resource: `${g.base}/telegram` }),
    });
    assert.equal(again2.json.error, 'invalid_target');
    assert.equal((await req(g.base, '/token', { method: 'POST', ...form({ grant_type: 'password', client_id: CLAUDE }) })).json.error, 'unsupported_grant_type');
  } finally {
    await g.close();
  }
});

test('обновление: новый токен при каждом обновлении, старый живёт в окне ожидания', async () => {
  const g = await startGateway();
  try {
    const first = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    const refresh = (token) => req(g.base, '/token', { method: 'POST', ...form({ grant_type: 'refresh_token', refresh_token: token, client_id: CLAUDE }) });
    const r1 = await refresh(first.token.json.refresh_token);
    assert.equal(r1.status, 200);
    assert.notEqual(r1.json.refresh_token, first.token.json.refresh_token);
    // Два узла Claude обновили одним и тем же токеном почти одновременно — оба получили доступ.
    const r2 = await refresh(first.token.json.refresh_token);
    assert.equal(r2.status, 200);
    assert.equal((await refresh(r1.json.refresh_token)).status, 200);
    // Чужой клиент токеном не воспользуется.
    const foreign = await req(g.base, '/token', { method: 'POST', ...form({ grant_type: 'refresh_token', refresh_token: r2.json.refresh_token, client_id: CLAUDE_CODE }) });
    assert.equal(foreign.json.error, 'invalid_grant');
    assert.equal((await refresh('gwr_nope')).json.error, 'invalid_grant');
    // Окно ожидания истекло.
    const g2 = g.gw.oauth;
    const realNow = g2.now;
    g2.now = () => realNow() + 11 * 60_000;
    try {
      assert.equal((await refresh(first.token.json.refresh_token)).json.error, 'invalid_grant');
    } finally {
      g2.now = realNow;
    }
  } finally {
    await g.close();
  }
});

test('отзыв: RFC 7009 и с главной страницы; токен одного коннектора не подходит другому', async () => {
  const g = await startGateway();
  try {
    const t = await authorizeAndToken(g.base, { clientId: CLAUDE, redirectUri: CALLBACK, resource: `${g.base}/bybit` });
    const call = (p, token) => req(g.base, p, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: '{}' });
    const cross = await call('/telegram', t.token.json.access_token);
    assert.equal(cross.status, 401);
    assert.match(cross.headers.get('www-authenticate'), /another connector/);
    const revoke = await req(g.base, '/revoke', { method: 'POST', ...form({ token: t.token.json.refresh_token, client_id: CLAUDE }) });
    assert.equal(revoke.status, 200);
    assert.equal((await call('/bybit', t.token.json.access_token)).status, 401);
    assert.equal(g.gw.oauth.grants().length, 0);
  } finally {
    await g.close();
  }
});
