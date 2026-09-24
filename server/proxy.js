// Передача запросов коннектору (обратный прокси) — HTTP, потоки SSE и WebSocket.
// Потоки не буферизуются: события уходят клиенту сразу. Коннектору не передаются
// заголовки, которые адресованы шлюзу: Authorization (токен OAuth), Cookie (вход
// владельца) и любые X-Gateway-* от клиента — их шлюз ставит сам.

import http from 'node:http';

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);
const DROP = new Set(['authorization', 'cookie', 'forwarded', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip']);

// Соединение с коннектором — на один запрос: даже если разметка тела где-то разойдётся,
// хвост чужого ответа не достанется следующему запросу.
const agent = new http.Agent({ keepAlive: false, maxSockets: 256 });

// У этих методов тела не бывает: запрос с телом — попытка протащить второй запрос.
const BODYLESS = new Set(['GET', 'HEAD', 'DELETE', 'OPTIONS', 'TRACE']);

function requestHeaders(req, extra, { upgrade = false } = {}) {
  const listed = new Set(
    String(req.headers.connection ?? '')
      .toLowerCase()
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const out = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const k = name.toLowerCase();
    if (HOP_BY_HOP.has(k) || listed.has(k) || DROP.has(k) || k.startsWith('x-gateway-')) continue;
    out[k] = value;
  }
  if (upgrade) {
    out.connection = 'Upgrade';
    out.upgrade = req.headers.upgrade;
  }
  return { ...out, ...extra };
}

function responseHeaders(headers, extra = {}) {
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(name.toLowerCase())) out[name] = value;
  }
  return { ...out, ...extra };
}

// HTTP-запрос → коннектор. extra — заголовки шлюза, responseExtra — добавить к ответу,
// path — нормализованный путь с запросом (по нему шлюз выбрал маршрут).
export function forward(req, res, upstream, extra, { logger, responseExtra = {}, path = req.url } = {}) {
  const target = new URL(upstream);
  const chunked = req.headers['transfer-encoding'] !== undefined;
  const hasBody = chunked || Number(req.headers['content-length'] ?? 0) > 0;
  if (hasBody && BODYLESS.has(req.method)) {
    req.resume();
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'close' });
    res.end('A request body is not allowed with this method\n');
    return;
  }
  const headers = requestHeaders(req, extra);
  // Тело частями — частями и дальше: без разметки коннектор принял бы его за второй запрос.
  if (chunked) {
    delete headers['content-length'];
    headers['transfer-encoding'] = 'chunked';
  }
  const out = http.request({
    hostname: target.hostname,
    port: target.port || 80,
    method: req.method,
    path,
    headers,
    agent,
  });
  out.on('response', (up) => {
    if (res.headersSent || res.destroyed) {
      up.resume();
      return;
    }
    res.writeHead(up.statusCode ?? 502, responseHeaders(up.headers, responseExtra));
    // Заголовки — сразу: у потока SSE первое событие может прийти нескоро.
    res.flushHeaders?.();
    up.pipe(res);
    up.on('error', () => res.destroy());
  });
  out.on('error', (err) => {
    logger?.warn(`коннектор ${target.host} недоступен: ${err.code ?? err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('Connector is unavailable\n');
    } else {
      res.destroy();
    }
  });
  // Клиент ушёл, не дождавшись ответа: обрываем и запрос к коннектору — для MCP это
  // отмена вызова.
  res.on('close', () => {
    if (!res.writableFinished) out.destroy();
  });
  if (hasBody) {
    req.pipe(out);
  } else {
    req.resume();
    out.end();
  }
}

// Запрос на WebSocket → коннектор; после 101 байты идут напрямую в обе стороны.
// tunnels — набор открытых соединений (шлюз закрывает их при остановке).
export function forwardUpgrade(req, socket, head, upstream, extra, { logger, tunnels, path = req.url } = {}) {
  const target = new URL(upstream);
  const out = http.request({
    hostname: target.hostname,
    port: target.port || 80,
    method: 'GET',
    path,
    headers: requestHeaders(req, extra, { upgrade: true }),
  });
  out.on('upgrade', (up, upSocket, upHead) => {
    const lines = [`HTTP/1.1 ${up.statusCode} ${up.statusMessage || 'Switching Protocols'}`];
    for (let i = 0; i < up.rawHeaders.length; i += 2) lines.push(`${up.rawHeaders[i]}: ${up.rawHeaders[i + 1]}`);
    socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (upHead?.length) socket.write(upHead);
    if (head?.length) upSocket.write(head);
    upSocket.on('error', () => socket.destroy());
    socket.on('error', () => upSocket.destroy());
    upSocket.on('close', () => socket.destroy());
    socket.on('close', () => upSocket.destroy());
    // Одна сторона закрыла свою половину, а другая не отвечает тем же — не держим вечно.
    const reap = () => setTimeout(() => {
      socket.destroy();
      upSocket.destroy();
    }, 10_000).unref();
    socket.on('end', reap);
    upSocket.on('end', reap);
    if (tunnels) {
      const pair = { socket, upSocket };
      tunnels.add(pair);
      socket.on('close', () => tunnels.delete(pair));
    }
    upSocket.setNoDelay?.(true);
    socket.setNoDelay?.(true);
    upSocket.pipe(socket);
    socket.pipe(upSocket);
  });
  // Коннектор отказал в апгрейде — его ответ уходит клиенту как есть.
  out.on('response', (up) => {
    const lines = [`HTTP/1.1 ${up.statusCode} ${up.statusMessage}`];
    for (let i = 0; i < up.rawHeaders.length; i += 2) {
      if (!HOP_BY_HOP.has(up.rawHeaders[i].toLowerCase())) lines.push(`${up.rawHeaders[i]}: ${up.rawHeaders[i + 1]}`);
    }
    lines.push('Connection: close');
    socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    up.pipe(socket);
  });
  out.on('error', (err) => {
    logger?.warn(`коннектор ${target.host} недоступен (WebSocket): ${err.code ?? err.message}`);
    socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  out.end();
}
