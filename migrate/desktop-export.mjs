#!/usr/bin/env node
// Перенос настроек коннекторов из Claude Desktop (macOS) в формат сервера.
//
//   node migrate/desktop-export.mjs <папка-результата>
//
// Claude Desktop хранит настройки расширений в
// ~/Library/Application Support/Claude/Claude Extensions Settings/<id>.json, а поля,
// помеченные в манифесте как секретные, шифрует через Electron safeStorage: ключ
// лежит в Связке ключей («Claude Safe Storage»). macOS спросит разрешение на доступ
// к нему — это нормально, нажмите «Разрешить».
//
// Результат: <папка>/<коннектор>/settings.json (права 0600) — ровно то, что сервер
// читает из папки данных коннектора. Секреты на экран не выводятся.

import { execFileSync } from 'node:child_process';
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SETTINGS_DIR = path.join(os.homedir(), 'Library/Application Support/Claude/Claude Extensions Settings');
const EXTENSIONS = {
  bybit: 'local.mcpb.sergei-grigorov.bybit-mcp',
  telegram: 'local.mcpb.sergei-grigorov.telegram',
};
// Поля, которые на сервере не переносятся: папки на диске этого компьютера.
const SKIP = { telegram: ['upload_dirs', 'download_dir'] };
const PREFIX = '__encrypted__:';

function safeStorageKey() {
  const password = execFileSync('security', ['find-generic-password', '-w', '-s', 'Claude Safe Storage', '-a', 'Claude Key'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim();
  // Chromium OSCrypt (macOS): PBKDF2-SHA1, соль «saltysalt», 1003 итерации, AES-128.
  return pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1');
}

function decrypt(value, key) {
  const raw = Buffer.from(value.slice(PREFIX.length), 'base64');
  if (raw.subarray(0, 3).toString('latin1') !== 'v10') throw new Error('неизвестный формат шифрования');
  const decipher = createDecipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
  return Buffer.concat([decipher.update(raw.subarray(3)), decipher.final()]).toString('utf8');
}

function mask(v) {
  if (typeof v !== 'string') return JSON.stringify(v);
  return v.length <= 6 ? '***' : `${v.slice(0, 3)}…(${v.length})`;
}

const outDir = process.argv[2];
if (!outDir) {
  console.error('Укажите папку для результата: node migrate/desktop-export.mjs <папка>');
  process.exit(2);
}

let key = null;
for (const [name, id] of Object.entries(EXTENSIONS)) {
  const file = path.join(SETTINGS_DIR, `${id}.json`);
  if (!fs.existsSync(file)) {
    console.log(`${name}: настроек в Claude Desktop нет (${file})`);
    continue;
  }
  const { userConfig = {} } = JSON.parse(fs.readFileSync(file, 'utf8'));
  const values = {};
  const report = [];
  for (const [field, value] of Object.entries(userConfig)) {
    if (SKIP[name]?.includes(field)) {
      report.push(`${field}: пропущено (папка на этом компьютере)`);
      continue;
    }
    if (typeof value === 'string' && value.startsWith(PREFIX)) {
      key ??= safeStorageKey();
      values[field] = decrypt(value, key);
      report.push(`${field}: секрет, ${values[field].length} символов`);
    } else {
      values[field] = value;
      report.push(`${field}: ${typeof value === 'string' ? mask(value) : JSON.stringify(value)}`);
    }
  }
  const target = path.join(outDir, name, 'settings.json');
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, `${JSON.stringify({ version: 1, updated: new Date().toISOString(), values }, null, 1)}\n`, { mode: 0o600 });
  console.log(`${name}: ${target}\n  ${report.join('\n  ')}`);
}
