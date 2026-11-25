// Turns pasted indicators into typed IOCs for Generic.Detection.IOCSweep.
// Accepts one indicator per line, "type,value[,note]" lines, defanged
// values (hxxp, [.], (.)) and URLs (reduced to their host).

export type IocType = 'sha256' | 'sha1' | 'md5' | 'ip' | 'domain' | 'path' | 'filename';
export const IOC_TYPES: IocType[] = ['sha256', 'sha1', 'md5', 'ip', 'domain', 'path', 'filename'];

export interface Ioc { type: IocType; value: string; note: string }
export interface ParseResult { iocs: Ioc[]; rejected: string[] }

const TYPE_SET = new Set<string>(IOC_TYPES);
const MAX_IOCS = 5000;

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*$/i;
const DOMAIN = /^(?=.{3,253}$)([a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;
const WIN_PATH = /^[a-z]:[\\/]/i;
const FILENAME = /^[^\\/:*?"<>|\r\n]+\.[a-z0-9]{1,8}$/i;

export function refang(s: string): string {
  return s.trim()
    .replace(/^hxxp/i, 'http')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
    .replace(/\[:\]/g, ':');
}

export function classify(raw: string): IocType | null {
  const v = raw.trim();
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  if (IPV4.test(v) || (IPV6.test(v) && v.includes(':'))) return 'ip';
  if (WIN_PATH.test(v) || v.startsWith('/')) return 'path';
  if (DOMAIN.test(v)) return /\.(exe|dll|ps1|bat|cmd|vbs|js|jar|scr|zip|rar|7z|doc|docx|xls|xlsx|pdf|lnk|hta|msi|iso|bin|sh|py)$/i.test(v) ? 'filename' : 'domain';
  if (FILENAME.test(v)) return 'filename';
  return null;
}

function hostOfUrl(v: string): string | null {
  try {
    return new URL(v).hostname || null;
  } catch {
    return null;
  }
}

export function parseIocs(text: string): ParseResult {
  const seen = new Set<string>();
  const iocs: Ioc[] = [];
  const rejected: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (iocs.length >= MAX_IOCS) break;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    let type: IocType | null = null;
    let value = trimmed;
    let note = '';
    const parts = trimmed.split(',');
    if (parts.length >= 2 && TYPE_SET.has(parts[0].trim().toLowerCase())) {
      type = parts[0].trim().toLowerCase() as IocType;
      value = parts[1];
      note = parts.slice(2).join(',').trim().replace(/^"([\s\S]*)"$/, '$1').replace(/""/g, '"');
    }
    value = refang(value);
    if (/^https?:\/\//i.test(value)) value = hostOfUrl(value) ?? value;
    if (type !== 'path') value = value.replace(/[.,;]+$/, '');
    type = type ?? classify(value);
    if (!type || !value) {
      rejected.push(trimmed);
      continue;
    }
    if (type !== 'path' && type !== 'filename') value = value.toLowerCase();
    const key = `${type}|${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    iocs.push({ type, value, note: note.slice(0, 200) });
  }
  return { iocs, rejected };
}

const csvCell = (s: string): string => (/[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

export function toCsv(iocs: Ioc[]): string {
  return ['Type,Value,Note', ...iocs.map(i => [i.type, i.value, i.note].map(csvCell).join(','))].join('\n') + '\n';
}
