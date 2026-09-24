// Владелец шлюза: пароль (scrypt), вход в браузере (сессия в cookie) и защита от
// подбора. Владелец один — тот, кто подключает коннекторы к Claude и меняет их
// настройки. Пароль хранится только как хеш: owner.json в папке данных.

import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

import { readJson, writeFileAtomic } from './store.js';

const scrypt = promisify(scryptCb);

const SCRYPT = { N: 1 << 15, r: 8, p: 1, keylen: 32 };
export const MIN_PASSWORD_LENGTH = 12;

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await scrypt(password.normalize('NFC'), salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: 128 * SCRYPT.N * SCRYPT.r * 2,
  });
  return { algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64'), hash: hash.toString('base64') };
}

export async function verifyPassword(password, record) {
  if (!record || record.algo !== 'scrypt' || typeof password !== 'string') return false;
  const expected = Buffer.from(record.hash, 'base64');
  const actual = await scrypt(password.normalize('NFC'), Buffer.from(record.salt, 'base64'), expected.length, {
    N: record.N,
    r: record.r,
    p: record.p,
    maxmem: 128 * record.N * record.r * 2,
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// Неудачные попытки: не больше perIp за окно с одного адреса и не больше global
// всего. Успешный вход сбрасывает счётчик адреса.
export class Throttle {
  constructor({ perIp = 5, global = 30, windowMs = 15 * 60_000, now = Date.now } = {}) {
    this.perIp = perIp;
    this.global = global;
    this.windowMs = windowMs;
    this.now = now;
    this.byIp = new Map();
    this.all = [];
  }

  prune(list) {
    const since = this.now() - this.windowMs;
    while (list.length && list[0] < since) list.shift();
    return list;
  }

  // Сколько секунд ждать (0 — можно пробовать).
  retryAfter(ip) {
    const mine = this.prune(this.byIp.get(ip) ?? []);
    const all = this.prune(this.all);
    const wait = (list) => Math.max(1, Math.ceil((list[0] + this.windowMs - this.now()) / 1000));
    if (mine.length >= this.perIp) return wait(mine);
    if (all.length >= this.global) return wait(all);
    return 0;
  }

  fail(ip) {
    const t = this.now();
    const mine = this.prune(this.byIp.get(ip) ?? []);
    mine.push(t);
    this.byIp.set(ip, mine);
    this.all.push(t);
    if (this.byIp.size > 10_000) this.byIp.clear();
  }

  success(ip) {
    this.byIp.delete(ip);
  }
}

export class OwnerAuth {
  constructor({ file, logger, now = Date.now, sessionTtlMs = 12 * 3600_000, idleTtlMs = 4 * 3600_000 }) {
    this.file = file;
    this.logger = logger;
    this.now = now;
    this.sessionTtlMs = sessionTtlMs;
    this.idleTtlMs = idleTtlMs;
    this.sessions = new Map();
    this.throttle = new Throttle({ now });
  }

  // Файл читается при каждой проверке: пароль могли сменить из командной строки.
  record() {
    return readJson(this.file, {})?.password ?? null;
  }

  hasPassword() {
    return Boolean(this.record());
  }

  async setPassword(password) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`Пароль должен быть не короче ${MIN_PASSWORD_LENGTH} символов`);
    }
    const data = readJson(this.file, {});
    data.version = 1;
    data.password = await hashPassword(password);
    data.updated = new Date(this.now()).toISOString();
    writeFileAtomic(this.file, `${JSON.stringify(data, null, 1)}\n`);
    // Все входы в браузере после смены пароля недействительны.
    this.sessions.clear();
  }

  // { ok } или { ok: false, retryAfter } — при превышении лимита пароль даже не проверяется.
  async check(password, ip) {
    const wait = this.throttle.retryAfter(ip);
    if (wait) return { ok: false, retryAfter: wait };
    const ok = await verifyPassword(password, this.record());
    if (ok) {
      this.throttle.success(ip);
      return { ok: true };
    }
    this.throttle.fail(ip);
    this.logger?.warn(`неверный пароль владельца с адреса ${ip}`);
    return { ok: false, retryAfter: this.throttle.retryAfter(ip) || 0 };
  }

  createSession() {
    const id = randomBytes(32).toString('base64url');
    const t = this.now();
    this.sessions.set(id, { created: t, seen: t, csrf: randomBytes(24).toString('base64url') });
    return id;
  }

  session(id) {
    if (typeof id !== 'string' || !id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    const t = this.now();
    if (t - s.created > this.sessionTtlMs || t - s.seen > this.idleTtlMs) {
      this.sessions.delete(id);
      return null;
    }
    s.seen = t;
    return s;
  }

  endSession(id) {
    this.sessions.delete(id);
  }
}
