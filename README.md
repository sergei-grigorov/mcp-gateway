# Шлюз коннекторов Claude на сервере

Коннекторы Bybit и Telegram работают как локальные расширения Claude Desktop (`.mcpb`). Этот шлюз позволяет разместить их на своём сервере (а коннектор Ubuntu, который выполняет команды на самом сервере, работает только так): тогда они доступны в claude.ai, в приложениях Claude Desktop и на телефоне (как удалённые коннекторы) и в Claude Code. Ключи, сессии Telegram и настройки хранятся на сервере.

```
claude.ai / Desktop / телефон / Claude Code
        │ HTTPS
Nginx Proxy Manager (TLS, agent.sergei-grigorov.com → 127.0.0.1:48678)
        │
шлюз :48678 ── OAuth 2.1, вход владельца, маршрутизация
   ├── /bybit     → контейнер bybit    (server/serve.js из bybit-mcp)
   ├── /telegram  → контейнер telegram (server/serve.js из telegram-mcp)
   ├── /ubuntu    → контейнер ubuntu (пересыльщик) → unix-сокет → служба systemd agent-ubuntu
   │                на самом сервере (server/serve.js из ubuntu-mcp, от root)
   └── /tracker   → контейнер tracker  (server/serve.js из yandex-tracker-mcp)
```

## Адреса

| Адрес | Что там |
|---|---|
| `https://agent.sergei-grigorov.com/bybit` | MCP-сервер Bybit — этот адрес вводится в Claude |
| `https://agent.sergei-grigorov.com/telegram` | MCP-сервер Telegram |
| `https://agent.sergei-grigorov.com/ubuntu` | MCP-сервер Ubuntu: команды и файлы этого сервера |
| `https://agent.sergei-grigorov.com/tracker` | MCP-сервер Yandex Tracker |
| `https://agent.sergei-grigorov.com/` | главная страница владельца: коннекторы, подключённые приложения, смена пароля |
| `…/bybit/settings`, `…/telegram/settings`, `…/ubuntu/settings`, `…/tracker/settings` | настройки коннекторов — те же поля, что в Claude Desktop |
| `…/telegram/accounts/` | вход в аккаунты Telegram (QR-код или номер) и выход |
| `…/telegram/files/` | файлы, которые Claude сохранил из Telegram |

Страницы открываются после входа по **паролю владельца**. Этим же паролем подтверждается подключение коннектора к Claude.

## Подключение к Claude

**claude.ai (и тем самым Claude Desktop и телефон):** Settings → Connectors → Add custom connector → название `Bybit`, адрес `https://agent.sergei-grigorov.com/bybit` → Add → Connect. Откроется страница шлюза «Разрешить доступ?»: введите пароль владельца и нажмите «Разрешить». Затем так же подключите `Telegram` с адресом `…/telegram`. Название коннектора пишите латиницей: с кириллическим названием claude.ai не вызывает инструменты.

Коннекторы, подключённые в claude.ai, появляются в Claude Desktop и мобильных приложениях сами. Локальные расширения Bybit и Telegram в Claude Desktop после этого лучше выключить (Settings → Extensions): иначе у модели будет два набора одинаковых инструментов.

**Claude Code:**

```bash
claude mcp add --transport http -s user bybit https://agent.sergei-grigorov.com/bybit
claude mcp add --transport http -s user telegram https://agent.sergei-grigorov.com/telegram
claude mcp add --transport http -s user ubuntu https://agent.sergei-grigorov.com/ubuntu
```

Затем `/mcp` → выбрать сервер → Authenticate: откроется та же страница разрешения. Оповещения Bybit и поток сообщений Telegram для `Monitor` работают через адреса `wss://agent.sergei-grigorov.com/…`.

Отозвать доступ любого приложения можно на главной странице шлюза.

## Как это защищено

- **Шлюз — единственный вход.** Коннекторы слушают только внутреннюю сеть Docker, шлюз — только `127.0.0.1:48678` (снаружи его публикует Nginx Proxy Manager с TLS). Запрос по `http://` перенаправляется на `https://`, с чужим `Host` — отклоняется.
- **OAuth 2.1** (спецификация MCP 2025-11-25 и 2026-07-28): код авторизации только с PKCE S256; токены привязаны к коннектору (RFC 8707) — токен для Bybit не подходит Telegram; токены хранятся только в виде хешей SHA-256; токен доступа живёт сутки, токен обновления — 90 дней и меняется при каждом обновлении. Прежний токен обновления ещё 10 минут принимается: запросы Claude приходят с разных узлов и могут обновлять почти одновременно. Приложение, не указавшее коннектор (`resource`), получает доступ ко всем коннекторам — страница разрешения так и пишет: «Все коннекторы».
- **Кто может получить токен.** Разрешение выдаёт только владелец, введя пароль на странице разрешения. Вернуть код можно только в Claude (`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/…`) или в локальное приложение (`http://localhost`, как у Claude Code); другие адреса добавляются переменной `REDIRECT_URIS`. Документы клиентов Claude и Claude Code встроены в шлюз (CIMD); остальные клиенты регистрируются сами (RFC 7591).
- **Пароль владельца** хранится как хеш scrypt в `data/gateway/owner.json`. После 5 неверных попыток с одного адреса (и 30 со всех) вход закрывается на 15 минут.
- **Страницы владельца** — только после входа (cookie `__Host-gw`: `Secure`, `HttpOnly`, `SameSite=Lax`, 12 часов); изменения принимаются только со своих страниц (проверка `Origin`).
- **Коннекторы** принимают запросы только с общим секретом шлюза (`GATEWAY_SECRET`) и не видят ни токенов OAuth, ни cookie владельца. Адреса WebSocket для `Monitor` содержат случайный токен и проверяются самим коннектором. Шлюз передаёт коннектору нормализованный путь, каждый запрос — отдельным соединением и с размеченным телом; запросы `GET`/`HEAD`/`DELETE` с телом отклоняются (защита от подмены запроса).
- **Контейнеры** работают от непривилегированного пользователя, с файловой системой только для чтения, без capabilities и с ограничением памяти. Журналы Docker ротируются (3 файла по 10 МБ).
- **Коннектор Ubuntu** — исключение: он выполняет команды на самом сервере от root, поэтому работает службой systemd, а не в контейнере. Порт он не открывает: слушает unix-сокет `run/ubuntu/http.sock` (папка `root:1000`, 0750), а шлюз достаёт до него через контейнер-пересыльщик `ubuntu`. Подробности — README `ubuntu-mcp`.

## Выкладка

На сервере всё лежит в `/opt/stack/agent`:

```
docker-compose.yml   ← mcp-gateway/deploy/docker-compose.yml
.env                 PUBLIC_URL=https://agent.sergei-grigorov.com, GATEWAY_SECRET=…
mcp-gateway/ bybit-mcp/ telegram-mcp/ ubuntu-mcp/ yandex-tracker-mcp/   исходники (кладёт deploy.sh)
data/gateway   owner.json, oauth.json
data/bybit     settings.json
data/telegram  settings.json, accounts/ (сессии Telegram)
data/ubuntu    settings.json коннектора Ubuntu
data/tracker   settings.json коннектора Yandex Tracker (OAuth-токен)
files/telegram скачанные файлы
run/ubuntu     unix-сокет службы agent-ubuntu (/etc/systemd/system/agent-ubuntu.service)
runtime/       Node.js и ripgrep для службы agent-ubuntu
```

Папки `data/` и `files/` принадлежат uid 1000 (пользователь `node` в контейнерах), права 0700; файлы с секретами — 0600.

**Обновление** (исходники всех проектов берутся из `~/Connectors`):

```bash
DEPLOY_HOST=root@89.22.236.55 sh deploy/deploy.sh
```

Скрипт копирует исходники, ставит или обновляет службу коннектора Ubuntu (`ubuntu-mcp/deploy/install.sh`: Node.js и ripgrep — официальные сборки с проверкой SHA-256 в `runtime/`, от apt сервера не зависят), собирает образы, перезапускает контейнеры и чистит старые образы. Данные и `.env` не трогаются. Нужен доступ по SSH (удобнее по ключу).

**Первая выкладка** на новом сервере: создать `/opt/stack/agent/.env` (права 0600):

```
PUBLIC_URL=https://agent.example.com
GATEWAY_SECRET=<openssl rand -hex 32>
```

затем `deploy.sh` и пароль владельца:

```bash
cd /opt/stack/agent && docker compose exec gateway node server/cli.js set-password
```

В Nginx Proxy Manager — proxy host на `127.0.0.1:48678` с сертификатом и включённой поддержкой WebSocket.

## Администрирование

```bash
cd /opt/stack/agent
docker compose ps                                  # состояние
docker compose logs -f gateway                     # журнал шлюза: запросы, выдача и отзыв доступа
docker compose logs -f bybit telegram tracker      # журналы коннекторов
journalctl -u agent-ubuntu -f                      # журнал коннектора Ubuntu (служба systemd)
docker compose exec gateway node server/cli.js info
docker compose exec gateway node server/cli.js set-password
docker compose exec gateway node server/cli.js token /bybit --ttl 600
```

`token` выдаёт короткий токен доступа к одному коннектору — чтобы проверить его без приложения (`Authorization: Bearer …`).

## Перенос настроек из Claude Desktop

`migrate/desktop-export.mjs` забирает настройки локальных расширений Bybit и Telegram из Claude Desktop (секретные поля расшифровываются ключом из Связки ключей macOS — система спросит разрешение) и пишет `settings.json` для сервера:

```bash
node migrate/desktop-export.mjs /tmp/export
```

Папки на диске (`upload_dirs`, `download_dir`) не переносятся: на сервере их задаёт сам сервер.

Сессия Telegram — файл `~/.telegram-mcp/accounts/<имя>.json` — переносится в `data/telegram/accounts/`. **Одну и ту же сессию нельзя использовать с двух адресов одновременно**: Telegram сочтёт это кражей ключа (`AUTH_KEY_DUPLICATED`) и завершит сессию. Поэтому файл переносится, а не копируется, и локальное расширение Telegram после переноса нужно выключить. Если Telegram нужен и локально, войдите там заново — получится отдельная сессия.

## Если Claude не подключается

- Журнал шлюза показывает каждый запрос Claude (`docker compose logs -f gateway`): обнаружение (`/.well-known/…`), `/authorize`, `/token`, запросы к `/bybit`.
- Если после «Разрешить» Claude пишет, что не смог воспользоваться выданным доступом, а запросов к `/bybit` в журнале нет, — это известная ошибка claude.ai с коннекторами на пути, отличном от `/mcp` ([anthropics/claude-ai-mcp#878](https://github.com/anthropics/claude-ai-mcp/issues/878)). Попробуйте адрес `https://agent.sergei-grigorov.com/bybit/mcp` — шлюз принимает оба. Надёжный обход — отдельные поддомены (`bybit.agent…/mcp`): это DNS-запись и proxy host в Nginx Proxy Manager, код менять не нужно.
- 502 — контейнер коннектора не запущен: `docker compose ps`, `docker compose logs bybit`.

## Разработка

```bash
npm test          # тесты: OAuth, вход владельца, прокси (node:test, без зависимостей)
```

- `server/index.js` — запуск; `server/config.js` — переменные окружения;
- `server/app.js` — маршрутизация, страницы владельца, проверка токенов;
- `server/oauth.js` — сервер авторизации: метаданные, CIMD, регистрация, коды, токены, отзыв;
- `server/owner.js` — пароль владельца, вход в браузере, защита от подбора;
- `server/proxy.js` — передача запросов коннекторам (HTTP, SSE, WebSocket);
- `server/pages.js` — страницы; `server/cli.js` — администрирование;
- `deploy/` — docker-compose и скрипт выкладки; `migrate/` — перенос настроек из Claude Desktop.

Совместимость проверена официальным клиентом `@modelcontextprotocol/client` 2.0.0 (регистрация через CIMD и DCR, протокол 2025-11-25 и 2026-07-28) и набором `@modelcontextprotocol/conformance`.
