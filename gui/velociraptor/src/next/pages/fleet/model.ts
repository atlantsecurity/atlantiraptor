import type { ApiClient } from '../../lib/types';
import { toDate } from '../../lib/format';

export const DAY_MS = 24 * 3600 * 1000;
export const ONLINE_MS = 15 * 60 * 1000;

export type OsKey = 'windows' | 'linux' | 'darwin' | 'other';
export const UPGRADE: Record<Exclude<OsKey, 'darwin' | 'other'>, { artifact: string; tool: string; label: string }> = {
  windows: { artifact: 'Admin.Client.Upgrade.Windows', tool: 'WindowsMSI', label: 'Windows' },
  linux: { artifact: 'Admin.Client.Upgrade.Debian', tool: 'VelociraptorDebian', label: 'Linux (Debian)' },
};

export function osKey(c: ApiClient): OsKey {
  const s = (c.os_info?.system ?? '').toLowerCase();
  return s === 'windows' ? 'windows' : s === 'linux' ? 'linux' : s === 'darwin' ? 'darwin' : 'other';
}

export function lastSeenMs(c: ApiClient): number {
  return toDate(c.last_seen_at as number)?.getTime() ?? 0;
}

// Compares dotted versions numerically ("0.77.10" > "0.77.4").
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map(x => parseInt(x, 10));
  const pb = b.split(/[.\-+]/).map(x => parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number.isNaN(pa[i]) ? 0 : pa[i] ?? 0;
    const y = Number.isNaN(pb[i]) ? 0 : pb[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

export interface FleetStats {
  total: number;
  online: number;
  stale7: ApiClient[];
  stale30: ApiClient[];
  latest: string;
  versions: { version: string; count: number; outdated: boolean }[];
  outdated: ApiClient[];
}

export function fleetStats(clients: ApiClient[], now = Date.now()): FleetStats {
  const versionOf = (c: ApiClient) => c.agent_information?.version || 'unknown';
  const known = clients.map(versionOf).filter(v => v !== 'unknown');
  const latest = known.reduce((m, v) => (compareVersions(v, m) > 0 ? v : m), known[0] ?? '');
  const counts = new Map<string, number>();
  clients.forEach(c => counts.set(versionOf(c), (counts.get(versionOf(c)) ?? 0) + 1));
  const versions = Array.from(counts.entries())
    .map(([version, count]) => ({ version, count, outdated: version !== 'unknown' && !!latest && compareVersions(version, latest) < 0 }))
    .sort((a, b) => (a.version === 'unknown' ? 1 : b.version === 'unknown' ? -1 : compareVersions(b.version, a.version)));
  const age = (c: ApiClient) => now - lastSeenMs(c);
  return {
    total: clients.length,
    online: clients.filter(c => age(c) < ONLINE_MS).length,
    stale7: clients.filter(c => age(c) >= 7 * DAY_MS && age(c) < 30 * DAY_MS),
    stale30: clients.filter(c => age(c) >= 30 * DAY_MS),
    latest,
    versions,
    outdated: clients.filter(c => {
      const v = versionOf(c);
      return v !== 'unknown' && !!latest && compareVersions(v, latest) < 0;
    }),
  };
}
