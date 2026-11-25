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
