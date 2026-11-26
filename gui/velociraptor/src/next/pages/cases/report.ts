// Builds a self-contained HTML report for a case and downloads it. Every
// value is escaped: case content and alert data can come from endpoints.
import { STATUS_LABEL, type CaseLink, type CaseRecord } from './model';

const esc = (v: unknown): string => String(v ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const when = (ms: number): string => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '');

function linkRow(l: CaseLink): string {
  const where = l.kind === 'flow' ? `${l.clientId ?? ''} / ${l.ref}` : l.ref;
  return `<tr><td>${esc(l.kind)}</td><td>${esc(l.label)}</td><td><code>${esc(where)}</code></td><td>${esc(l.addedBy)}</td><td>${esc(when(l.addedAt))}</td></tr>`;
}

export function buildCaseReport(id: string, c: CaseRecord, creator: string): string {
  const timeline = [...c.timeline].sort((a, b) => a.at - b.at)
    .map(e => `<tr><td>${esc(when(e.at))}</td><td>${esc(e.by)}</td><td>${esc(e.kind)}</td><td class="pre">${esc(e.text)}</td></tr>`)
    .join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(c.title)} – case report</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:32px auto;padding:0 16px;color:#1a1a1a}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:13px} td,th{border:1px solid #e3e3e3;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f6f6f6} code{font-size:12px} .pre{white-space:pre-wrap;word-break:break-word} .meta td:first-child{width:140px;color:#555}
</style></head><body>
<h1>${esc(c.title)}</h1>
<div>Case ${esc(id)} · exported ${esc(when(Date.now()))}</div>
<h2>Overview</h2>
<table class="meta">
<tr><td>Status</td><td>${esc(STATUS_LABEL[c.status])}</td></tr>
<tr><td>Severity</td><td>${esc(c.severity)}</td></tr>
<tr><td>Owner</td><td>${esc(c.owner || 'Unassigned')}</td></tr>
<tr><td>Opened by</td><td>${esc(creator)}</td></tr>
</table>
<h2>Summary</h2><div class="pre">${esc(c.summary || 'No summary.')}</div>
<h2>Linked items (${c.links.length})</h2>
${c.links.length ? `<table><tr><th>Type</th><th>Item</th><th>Reference</th><th>Added by</th><th>Added</th></tr>${c.links.map(linkRow).join('')}</table>` : '<p>None.</p>'}
<h2>Timeline</h2>
<table><tr><th>Time</th><th>By</th><th>Event</th><th>Detail</th></tr>${timeline}</table>
</body></html>`;
}

export function downloadCaseReport(id: string, c: CaseRecord, creator: string) {
  const blob = new Blob([buildCaseReport(id, c, creator)], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `case-${c.title.replace(/[^\w.-]+/g, '_').slice(0, 60) || id}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
}
