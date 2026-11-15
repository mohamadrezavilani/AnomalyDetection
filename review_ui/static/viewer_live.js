'use strict';
// Refresh only the home list. Never reload a request/evidence detail page.
let refreshing = false;
async function refreshHome() {
  const current = document.getElementById('behavior-list');
  if (!current || refreshing || document.hidden ||
      ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
  refreshing = true;
  try {
    const response = await fetch(window.location.href, {cache: 'no-store', credentials: 'same-origin'});
    if (!response.ok) throw new Error('refresh failed');
    const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
    const replacement = doc.getElementById('behavior-list');
    if (!replacement) throw new Error('missing list');
    const coverage = doc.getElementById('history-gap-notice');
    const oldCoverage = document.getElementById('history-gap-notice');
    if (coverage && oldCoverage) oldCoverage.replaceWith(coverage);
    if (current.dataset.page === '1') {
      current.replaceWith(replacement);
    } else if (current.dataset.generation !== replacement.dataset.generation) {
      document.getElementById('refresh-note').textContent = 'داده‌های جدید رسیده‌اند؛ برای ادامه، فهرست را از صفحهٔ اول باز کنید.';
    }
  } catch (_) {
    const note = document.getElementById('refresh-note');
    if (note) note.textContent = 'ارتباط تازه‌سازی برقرار نیست؛ داده‌های آخرین نمایش حفظ شده‌اند.';
  } finally { refreshing = false; }
}
let progressRefreshing = false;
async function refreshProgress() {
  if (progressRefreshing || document.hidden) return;
  const banner = document.getElementById('live-banner');
  if (!banner) return;
  progressRefreshing = true;
  try {
    const response = await fetch('/live-progress', {cache: 'no-store', credentials: 'same-origin'});
    if (!response.ok) throw new Error('progress unavailable');
    const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
    const replacement = doc.getElementById('live-banner');
    if (!replacement) throw new Error('missing progress');
    // An older full-page response must not overwrite a fresher progress read.
    const current = document.getElementById('live-banner');
    if (current) current.replaceWith(replacement);
  } catch (_) {
    const note = document.getElementById('progress-refresh-note');
    if (note) note.textContent = 'ارتباط تازه‌سازی پیشرفت برقرار نیست؛ آخرین وضعیت نمایش داده می‌شود.';
  } finally { progressRefreshing = false; }
}
window.setInterval(refreshHome, 30000);
window.setInterval(refreshProgress, 5000);
