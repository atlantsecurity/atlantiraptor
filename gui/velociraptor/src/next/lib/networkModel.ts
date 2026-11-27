// Pure helpers for the network allowlist screen (no React, no network).

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;

/** A problem with one entry (IP or CIDR), or null. Mirrors the server check loosely. */
export function entryProblem(raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  const [addr, bits, extra] = v.split('/');
  if (extra !== undefined) return `${v}: not an address or range`;
  const v4 = IPV4.test(addr) && addr.split('.').every(o => Number(o) <= 255);
  const v6 = addr.includes(':') && /^[0-9a-f:.]+$/i.test(addr);
  if (!v4 && !v6) return `${v}: not an IP address`;
  if (bits !== undefined) {
    const n = Number(bits);
    if (!/^\d+$/.test(bits) || n > (v4 ? 32 : 128)) return `${v}: bad range size`;
  }
  return null;
}

/** Splits free text (lines, commas, spaces) into entries. */
export function splitEntries(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean))];
}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}

/** Whether an IPv4 address is covered by the entries (IPv6 not evaluated: returns null). */
export function coveredBy(ip: string, entries: string[]): boolean | null {
  if (!IPV4.test(ip)) return null;
  const n = ipv4ToInt(ip);
  for (const e of entries) {
    const [addr, bits] = e.split('/');
    if (!IPV4.test(addr)) continue;
    const b = bits === undefined ? 32 : Number(bits);
    const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
    if (((n & mask) >>> 0) === ((ipv4ToInt(addr) & mask) >>> 0)) return true;
  }
  return false;
}

