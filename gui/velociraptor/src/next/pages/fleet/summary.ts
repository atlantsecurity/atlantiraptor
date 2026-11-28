// Fleet health as the server reports it (GET v1/atl/fleet), and the
// version maths done here: which version is newest per OS and which
// versions are behind. Kept free of app imports so it can be unit tested.
import { compareVersions } from './versions.ts';

export interface FleetHost {
  client_id: string;
  hostname: string;
  os: string;
  version: string;
  last_seen_at: number; // microseconds
}

export interface FleetVersionCount { os: string; version: string; count: number }

export interface FleetSummary {
  total: number;
  online: number;
  quiet_7_count: number;
  quiet_30_count: number;
  quiet_7: FleetHost[];
  quiet_30: FleetHost[];
  versions: FleetVersionCount[];
}

export interface VersionRow extends FleetVersionCount { latest: boolean; outdated: boolean }

export interface FleetVersions {
  rows: VersionRow[];
  latestByOs: Record<string, string>;
  outdatedByOs: Record<string, { count: number; versions: string[] }>;
  outdatedTotal: number;
}

const UNKNOWN = 'unknown';

/** Newest version per OS, and which versions of each OS are behind it. */
export function fleetVersions(counts: FleetVersionCount[]): FleetVersions {
  const latestByOs: Record<string, string> = {};
  for (const v of counts) {
    if (v.version === UNKNOWN) continue;
    const cur = latestByOs[v.os];
    if (!cur || compareVersions(v.version, cur) > 0) latestByOs[v.os] = v.version;
  }
  const outdatedByOs: FleetVersions['outdatedByOs'] = {};
  let outdatedTotal = 0;
  const rows = counts.map(v => {
    const latest = latestByOs[v.os];
    const outdated = v.version !== UNKNOWN && !!latest && compareVersions(v.version, latest) < 0;
    if (outdated) {
      const o = (outdatedByOs[v.os] ??= { count: 0, versions: [] });
      o.count += v.count;
      o.versions.push(v.version);
      outdatedTotal += v.count;
    }
    return { ...v, latest: v.version === latest, outdated };
  }).sort((a, b) => a.os.localeCompare(b.os)
    || (a.version === UNKNOWN ? 1 : b.version === UNKNOWN ? -1 : compareVersions(b.version, a.version)));
  return { rows, latestByOs, outdatedByOs, outdatedTotal };
}
