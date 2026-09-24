// Файлы данных шлюза: JSON с атомарной записью (временный файл + rename), права 0600,
// папка 0700. Запись откладывается и склеивает частые изменения.

import fs from 'node:fs';
import path from 'node:path';

export function writeFileAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

export function readJson(file, fallback) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
  return JSON.parse(text);
}

export class JsonFile {
  constructor(file, { defaults = {}, logger, delayMs = 300 } = {}) {
    this.file = file;
    this.logger = logger;
    this.delayMs = delayMs;
    this.data = { ...defaults, ...readJson(file, {}) };
    this.timer = null;
  }

  save() {
    if (this.timer) return;
    this.timer = setTimeout(() => this.flush(), this.delayMs);
    this.timer.unref?.();
  }

  flush() {
    clearTimeout(this.timer);
    this.timer = null;
    try {
      writeFileAtomic(this.file, `${JSON.stringify(this.data, null, 1)}\n`);
    } catch (err) {
      this.logger?.error(`не удалось сохранить ${path.basename(this.file)}: ${err.message}`);
    }
  }
}
