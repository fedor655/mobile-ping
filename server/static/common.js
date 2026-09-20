function esc(s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-store' });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return p(d.getDate()) + '.' + p(d.getMonth() + 1) + ' ' +
         p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function fmtSec(s) {
  s = Math.max(0, Math.round(s));
  return s < 60 ? s + ' с' : Math.floor(s / 60) + ' м ' + (s % 60) + ' с';
}

function fmtDur(a, b) {
  if (!a || !b) return '';
  return fmtSec(b - a);
}

function statusRu(s) {
  return { queued: 'в очереди', running: 'выполняется',
           done: 'готово', failed: 'сбой',
           error: 'ошибка', skipped: 'пропущено' }[s] || s;
}
