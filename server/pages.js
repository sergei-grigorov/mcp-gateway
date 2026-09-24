// Страницы шлюза: вход владельца, разрешение доступа для приложения (OAuth),
// главная страница со списком коннекторов и подключённых приложений. Без внешних
// ресурсов и без скриптов; стили — с nonce из Content-Security-Policy.

import { randomBytes } from 'node:crypto';

const STYLE = `
:root { --bg:#f5f6f8; --card:#fff; --text:#1c1d21; --muted:#6b7280; --line:#e3e5e8; --accent:#2a8bd8; --accent-2:#1f6fb0; --ok:#1f9d55; --err:#c83232; --warn-bg:#fff6e0; --warn-line:#f0c46b; }
@media (prefers-color-scheme: dark) { :root { --bg:#15171a; --card:#1e2125; --text:#eceef1; --muted:#9aa1ab; --line:#30343a; --accent:#4aa3ea; --accent-2:#7cbcf0; --ok:#4cc27d; --err:#ef6b6b; --warn-bg:#3a3120; --warn-line:#8a6d2c; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width:560px; margin:32px auto; padding:0 16px 48px; }
h1 { font-size:24px; margin:0 0 4px; }
h2 { font-size:16px; margin:0 0 12px; }
a { color:var(--accent); }
.sub, .muted { color:var(--muted); }
.sub { margin:0 0 20px; }
section { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; margin:0 0 16px; }
label { display:block; margin:0 0 12px; font-weight:500; }
input[type=password], input[type=text] { display:block; width:100%; margin-top:6px; padding:10px 12px; font:inherit; color:var(--text); background:transparent; border:1px solid var(--line); border-radius:10px; }
input:focus { outline:2px solid var(--accent); outline-offset:-1px; }
button { font:inherit; cursor:pointer; border:0; border-radius:10px; padding:10px 16px; background:var(--accent); color:#fff; font-weight:600; }
button:hover { background:var(--accent-2); }
button.secondary { background:none; color:var(--muted); border:1px solid var(--line); font-weight:500; }
button.danger { background:none; color:var(--err); border:1px solid var(--line); padding:6px 12px; font-weight:500; }
.actions { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
.warn { background:var(--warn-bg); border:1px solid var(--warn-line); border-radius:12px; padding:12px 14px; margin:0 0 16px; }
.err { color:var(--err); margin:0 0 12px; }
.ok { color:var(--ok); font-weight:600; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 14px; margin:0 0 16px; }
dt { color:var(--muted); }
dd { margin:0; word-break:break-word; }
ul.plain { list-style:none; margin:0; padding:0; }
ul.plain li { display:flex; justify-content:space-between; align-items:center; gap:12px; padding:10px 0; border-top:1px solid var(--line); }
ul.plain li:first-child { border-top:0; padding-top:0; }
ul.plain b { display:block; }
form.inline { margin:0; }
footer { color:var(--muted); font-size:13px; }
`;

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function newNonce() {
  return randomBytes(16).toString('base64');
}

// formAction — куда форма может отправлять и перенаправлять: Chrome применяет
// form-action и к перенаправлению после отправки (на странице разрешения — к адресу
// возврата в приложение).
export function pageHeaders(nonce, { formAction = "'self'" } = {}) {
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'none'; style-src 'nonce-${nonce}'; img-src data:; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    // same-origin, а не no-referrer: с no-referrer браузер отправляет форму с Origin: null.
    'Referrer-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
}

function layout({ title, nonce, body }) {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body><main>
${body}
</main></body>
</html>`;
}

const hidden = (name, value) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`;

export function renderSignIn({ nonce, siteName, next = '/', error = '' }) {
  return layout({
    title: `${siteName}: вход`,
    nonce,
    body: `
<h1>${escapeHtml(siteName)}</h1>
<p class="sub">Вход владельца: настройки коннекторов, аккаунты и подключённые приложения.</p>
<section>
<form method="post" action="/signin">
${hidden('next', next)}
${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
<label>Пароль владельца<input type="password" name="password" autocomplete="current-password" autofocus required></label>
<button type="submit">Войти</button>
</form>
</section>`,
  });
}

// Страница разрешения доступа (OAuth): кто просит, к какому коннектору, куда вернёт.
export function renderConsent({ nonce, siteName, request, clientName, clientNote, resourceTitle, resourceUrl, returnTo, knownReturn, error = '' }) {
  return layout({
    title: `${siteName}: разрешить доступ`,
    nonce,
    body: `
<h1>Разрешить доступ?</h1>
<p class="sub">Приложение просит доступ к коннектору от вашего имени. Разрешайте, только если вы сами сейчас подключаете коннектор — например, нажали Connect в настройках Claude.</p>
<section>
<dl>
<dt>Приложение</dt><dd><b>${escapeHtml(clientName)}</b>${clientNote ? `<br><span class="muted">${escapeHtml(clientNote)}</span>` : ''}</dd>
<dt>Коннектор</dt><dd><b>${escapeHtml(resourceTitle)}</b><br><span class="muted">${escapeHtml(resourceUrl)}</span></dd>
<dt>Возврат</dt><dd>${escapeHtml(returnTo)}</dd>
</dl>
${knownReturn ? '' : '<div class="warn">Адрес возврата не принадлежит Claude. Разрешайте, только если сами подключаете это приложение.</div>'}
<form method="post" action="/authorize">
${hidden('request', request)}
${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
<label>Пароль владельца<input type="password" name="password" autocomplete="current-password" autofocus></label>
<div class="actions">
<button type="submit" name="decision" value="allow">Разрешить</button>
<button type="submit" name="decision" value="deny" class="secondary">Отказать</button>
</div>
</form>
</section>
<footer>Приложение получит доступ ко всем инструментам коннектора, которые разрешены в его настройках. Отозвать доступ можно на главной странице ${escapeHtml(siteName)}.</footer>`,
  });
}

function formatDate(ms) {
  if (!ms) return '—';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

export function renderHome({ nonce, siteName, origin, routes, grants, notice = '', error = '' }) {
  const connectors = routes
    .map(
      (r) => `<li><div><b>${escapeHtml(r.title)}</b><span class="muted">Адрес для Claude: ${escapeHtml(origin + r.path)}</span></div><a href="${escapeHtml(r.path)}/settings">Настройки</a></li>`,
    )
    .join('');
  const apps = grants.length
    ? grants
        .map(
          (g) => `<li><div><b>${escapeHtml(g.clientName)} → ${escapeHtml(g.resourceTitle)}</b><span class="muted">подключено ${escapeHtml(formatDate(g.created))}, последний раз ${escapeHtml(formatDate(g.lastUsed))}</span></div>
<form method="post" action="/grants/revoke" class="inline">${hidden('grant', g.id)}<button type="submit" class="danger">Отозвать</button></form></li>`,
        )
        .join('')
    : '<li class="muted">Пока ни одного.</li>';
  return layout({
    title: siteName,
    nonce,
    body: `
<h1>${escapeHtml(siteName)}</h1>
<p class="sub">Коннекторы Claude на этом сервере.</p>
${notice ? `<section><span class="ok">${escapeHtml(notice)}</span></section>` : ''}
${error ? `<section><p class="err">${escapeHtml(error)}</p></section>` : ''}
<section><h2>Коннекторы</h2><ul class="plain">${connectors}</ul>
<p class="muted">Подключение: claude.ai → Settings → Connectors → Add custom connector, адрес — из списка выше. Claude откроет страницу разрешения: там нужен пароль владельца.</p></section>
<section><h2>Подключённые приложения</h2><ul class="plain">${apps}</ul></section>
<section><h2>Пароль владельца</h2>
<form method="post" action="/password">
<label>Текущий пароль<input type="password" name="current" autocomplete="current-password" required></label>
<label>Новый пароль <span class="muted">(не короче 12 символов)</span><input type="password" name="password" autocomplete="new-password" required></label>
<label>Ещё раз<input type="password" name="confirm" autocomplete="new-password" required></label>
<button type="submit">Сменить пароль</button>
</form></section>
<form method="post" action="/signout"><button type="submit" class="secondary">Выйти</button></form>`,
  });
}

export function renderMessage({ nonce, title, text, link = null }) {
  return layout({
    title,
    nonce,
    body: `<h1>${escapeHtml(title)}</h1><section><p>${escapeHtml(text)}</p>${link ? `<p><a href="${escapeHtml(link.href)}">${escapeHtml(link.text)}</a></p>` : ''}</section>`,
  });
}
