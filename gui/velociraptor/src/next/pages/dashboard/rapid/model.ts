// Pure helpers for Rapid hunt (no React, no network) so they can be
// unit tested.

export const RAPID_ARTIFACT = 'Generic.Detection.RapidHunt';

export interface Hit {
  source: string;
  time: number; // ms since epoch, 0 when unknown
  user: string;
  process: string;
  match: string;
  detail: string;
}

export interface HostHits {
  clientId: string;
  hostname: string;
  sources: string[];
  users: string[];
  last: number;
  hits: Hit[];
}

const str = (v: unknown) => (v === null || v === undefined ? '' : String(v));

function toMs(v: unknown): number {
  if (typeof v === 'number') return v > 1e12 ? v : v * 1000;
  const s = str(v);
  if (!s) return 0;
  if (/^\d+(\.\d+)?$/.test(s)) return toMs(Number(s));
  const t = Date.parse(s);
  return Number.isNaN(t) ? 0 : t;
}

/** Groups hunt result rows by machine, newest hit first; machines with the latest hits come first. */
export function groupByHost(rows: Record<string, unknown>[]): HostHits[] {
  const byHost = new Map<string, HostHits>();
  for (const r of rows) {
    const clientId = str(r.ClientId);
    if (!clientId) continue;
    let h = byHost.get(clientId);
    if (!h) {
      h = { clientId, hostname: str(r.Fqdn) || clientId, sources: [], users: [], last: 0, hits: [] };
      byHost.set(clientId, h);
    }
    const hit: Hit = {
      source: str(r.Source), time: toMs(r.Time), user: str(r.User),
      process: str(r.Process), match: str(r.Match), detail: str(r.Detail),
    };
    h.hits.push(hit);
    if (hit.source && !h.sources.includes(hit.source)) h.sources.push(hit.source);
    if (hit.user && !h.users.includes(hit.user)) h.users.push(hit.user);
    h.last = Math.max(h.last, hit.time);
  }
  const out = [...byHost.values()];
  for (const h of out) h.hits.sort((a, b) => b.time - a.time);
  return out.sort((a, b) => b.last - a.last || a.hostname.localeCompare(b.hostname));
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const DOMAIN = /^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}\.?$/i;

/** A user-facing problem with the indicator, or null when it is usable. */
export function indicatorProblem(raw: string): string | null {
  const v = raw.trim();
  if (v.length > 2048) return 'That is too long.';
  if (/\s/.test(v)) return 'Enter one domain, URL or IP address.';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    try {
      const host = new URL(v).hostname;
      return host ? null : 'That URL has no host.';
    } catch {
      return 'That is not a valid URL.';
    }
  }
  const m = IPV4.exec(v);
  if (m) return m.slice(1).every(o => Number(o) <= 255) ? null : 'That is not a valid IP address.';
  if (/^[0-9a-f:]+$/i.test(v) && v.includes(':')) return null;
  const host = v.split(/[/:]/)[0];
  return DOMAIN.test(host) ? null : 'Enter a domain (example.com), URL or IP address.';
}

// ------------------------------------------------- Kinds of indicator

export type RapidKind = 'web' | 'hash' | 'file' | 'process' | 'user';
export const RAPID_KINDS: RapidKind[] = ['web', 'hash', 'file', 'process', 'user'];
export const RAPID_KIND_LABEL: Record<RapidKind, string> = {
  web: 'Website or IP', hash: 'File hash', file: 'File name or path', process: 'Program', user: 'User',
};
export const RAPID_KIND_QUESTION: Record<RapidKind, string> = {
  web: 'visited', hash: 'has the file', file: 'has the file', process: 'ran', user: 'had activity by',
};

const HASH = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const WIN_PATH = /^[a-z]:[\\/]|^\\\\|^\//i;
const FILE_EXT = /\.(exe|dll|ps1|bat|cmd|vbs|js|jse|jar|scr|zip|rar|7z|docm?|xlsm?|pdf|lnk|hta|msi|iso|img|bin|sh|py|elf|so|dylib|app|pkg|dmg|sys)$/i;

/** Best guess of what kind of indicator this is. */
export function detectKind(raw: string): RapidKind {
  const v = raw.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)/g, '.');
  if (HASH.test(v)) return 'hash';
  if (WIN_PATH.test(v)) return 'file';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'web';
  if (/^[^\\@\s]+\\[^\\@\s]+$/.test(v)) return 'user'; // DOMAIN\user
  if (FILE_EXT.test(v)) return /\.(exe|scr|com)$/i.test(v) ? 'process' : 'file';
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return 'user'; // user@domain.tld (UPN)
  if (v.includes('.') || v.includes(':')) return 'web';
  return 'process';
}

/** Refanged value to hunt for. */
export function cleanIndicator(raw: string): string {
  return raw.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)/g, '.');
}

/** A user-facing problem with the indicator for this kind, or null. */
export function kindProblem(raw: string, kind: RapidKind): string | null {
  const v = cleanIndicator(raw);
  if (!v) return null;
  if (v.length > 2048) return 'That is too long.';
  switch (kind) {
    case 'web': return indicatorProblem(v);
    case 'hash': return HASH.test(v) ? null : 'Enter an MD5, SHA1 or SHA256 hash.';
    case 'file': return /[\r\n]/.test(v) ? 'Enter one file name or path.' : null;
    case 'process': return /[\\/\r\n]/.test(v) ? 'Enter a program name such as rclone.exe (use File for a full path).' : null;
    case 'user': return /\s/.test(v) ? 'Enter one user name, e.g. alice or CORP\\alice.' : null;
  }
}

// --------------------------------------------- Shared Rapid hunt history

export const RAPID_TAG = 'rapid-hunt';

export interface RapidEntry { huntId: string; indicator: string; kind: RapidKind; started: number; creator: string }

/** Description of a Rapid hunt, read back by parseRapidDescription. */
export function rapidDescription(indicator: string, kind: RapidKind): string {
  return kind === 'web' ? `Rapid hunt: ${indicator}` : `Rapid hunt (${kind}): ${indicator}`;
}

export function parseRapidDescription(d: string): { indicator: string; kind: RapidKind } | null {
  const m = /^Rapid hunt(?: \((web|hash|file|process|user)\))?: (.+)$/s.exec(d ?? '');
  return m ? { kind: (m[1] as RapidKind) ?? 'web', indicator: m[2] } : null;
}

// ------------------------------------------------ Pivots from tables

const USER_COL = /^(user|username|user_name|targetusername|subjectusername|owner|account|accountname|logonuser)$/i;
const PROC_COL = /^(name|process|processname|image|exe|binary|program|parentimage|parent)$/i;
const HASH_COL = /(md5|sha1|sha256|hash)/i;

/** The kind of indicator a cell holds, from its column name and value. */
export function pivotKind(column: string, value: string): RapidKind | null {
  const v = cleanIndicator(value);
  if (!v || v.length > 512 || /[\r\n]/.test(v)) return null;
  let k: RapidKind = detectKind(v);
  if (USER_COL.test(column) && !/[\\/]/.test(v.replace(/^[^\\]+\\/, ''))) k = 'user';
  else if (PROC_COL.test(column)) k = /[\\/]/.test(v) ? 'file' : 'process';
  else if (HASH_COL.test(column)) k = 'hash';
  if (k === 'process' && !USER_COL.test(column) && !PROC_COL.test(column) && !/\.(exe|scr|com)$/i.test(v)) {
    // A bare word in an unrelated column is not worth offering.
    return null;
  }
  return kindProblem(v, k) ? null : k;
}

