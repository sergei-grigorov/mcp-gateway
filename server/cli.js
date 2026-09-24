#!/usr/bin/env node
// Администрирование шлюза на сервере (те же переменные окружения, что у шлюза):
//
//   node server/cli.js set-password            задать пароль владельца (спросит дважды;
//                                              с --stdin — прочитает одну строку из stdin)
//   node server/cli.js token <путь> [--ttl с]  короткий токен доступа к коннектору (по
//                                              умолчанию на 10 минут) — проверить его без
//                                              приложения: Authorization: Bearer <токен>
//   node server/cli.js info                    коннекторы, приложения, токены
//
// В контейнере: docker compose exec gateway node server/cli.js …

import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import readline from 'node:readline';

import { loadConfig } from './config.js';
import { OwnerAuth, MIN_PASSWORD_LENGTH } from './owner.js';
import { readJson, writeFileAtomic } from './store.js';

const out = (s = '') => process.stdout.write(`${s}\n`);

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let prompted = false;
    rl._writeToOutput = (s) => {
      if (!prompted) {
        process.stdout.write(s);
        prompted = true;
      }
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function readLine() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8').split(/\r?\n/)[0];
}

const [command, ...args] = process.argv.slice(2);
let config;
try {
  config = loadConfig();
} catch (err) {
  out(`Ошибка настроек: ${err.message}`);
  process.exit(1);
}
const owner = new OwnerAuth({ file: path.join(config.dataDir, 'owner.json') });

switch (command) {
  case 'set-password': {
    let password;
    if (args.includes('--stdin')) {
      password = await readLine();
    } else {
      password = await askHidden('Новый пароль владельца: ');
      if ((await askHidden('Ещё раз: ')) !== password) {
        out('Пароли не совпали.');
        process.exit(1);
      }
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      out(`Пароль должен быть не короче ${MIN_PASSWORD_LENGTH} символов.`);
      process.exit(1);
    }
    await owner.setPassword(password);
    out('Пароль владельца задан. Входы в браузере, открытые до этого, завершатся после перезапуска шлюза.');
    break;
  }
  case 'token': {
    const routePath = args[0];
    const route = config.routes.find((r) => r.path === routePath);
    if (!route) {
      out(`Укажите коннектор: ${config.routes.map((r) => r.path).join(', ')}`);
      process.exit(1);
    }
    const i = args.indexOf('--ttl');
    const ttl = i >= 0 ? Number(args[i + 1]) : 600;
    if (!Number.isInteger(ttl) || ttl < 10 || ttl > 86_400) {
      out('--ttl: от 10 до 86400 секунд');
      process.exit(1);
    }
    const token = `gwc_${randomBytes(32).toString('base64url')}`;
    const file = path.join(config.dataDir, 'cli-tokens.json');
    const now = Date.now();
    const tokens = (readJson(file, {})?.tokens ?? []).filter((x) => x.expires_at > now);
    tokens.push({ hash: createHash('sha256').update(token).digest('hex'), route: route.path, created_at: now, expires_at: now + ttl * 1000 });
    writeFileAtomic(file, `${JSON.stringify({ tokens }, null, 1)}\n`);
    out(token);
    process.stderr.write(`Токен для ${config.origin}${route.path} на ${ttl} с.\n`);
    break;
  }
  case 'info': {
    const data = readJson(path.join(config.dataDir, 'oauth.json'), {});
    out(`Шлюз: ${config.origin}; пароль владельца ${owner.hasPassword() ? 'задан' : 'НЕ задан'}`);
    for (const r of config.routes) out(`  ${config.origin}${r.path} → ${r.upstream}`);
    const grants = Object.values(data.grants ?? {});
    out(`Приложения с доступом: ${grants.length}`);
    for (const g of grants) out(`  ${g.client_name} → ${g.resource ?? 'все коннекторы'}, последний раз ${new Date(g.last_used_at).toISOString()}`);
    out(`Зарегистрированных клиентов: ${Object.keys(data.clients ?? {}).length}`);
    break;
  }
  default:
    out('Команды: set-password [--stdin], token <путь> [--ttl секунды], info');
    process.exit(command ? 1 : 0);
}
