#!/usr/bin/env node
// Шлюз коннекторов Claude (MCP) на сервере: OAuth, вход владельца и маршрутизация
// по путям коннекторов. Настройки — переменные окружения (config.js).

import { Gateway } from './app.js';
import { loadConfig } from './config.js';

const line = (level, m) => `${new Date().toISOString()} ${level}${m}\n`;
export const logger = {
  info: (m) => process.stdout.write(line('', m)),
  warn: (m) => process.stdout.write(line('WARN ', m)),
  error: (m) => process.stderr.write(line('ERROR ', m)),
};

let config;
try {
  config = loadConfig();
} catch (err) {
  logger.error(err.message);
  process.exit(1);
}

const gateway = new Gateway({ config, logger });
if (!gateway.owner.hasPassword()) logger.warn('пароль владельца не задан: node server/cli.js set-password');
const address = await gateway.listen();
logger.info(
  `${config.origin} ← http://${address.address}:${address.port}; коннекторы: ${config.routes.map((r) => `${r.path} → ${r.upstream}`).join(', ')}`,
);

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  setTimeout(() => process.exit(0), 5000).unref();
  await gateway.close().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
