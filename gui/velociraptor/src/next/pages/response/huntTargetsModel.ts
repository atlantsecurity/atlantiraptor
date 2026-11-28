// Pure part of huntTargets, kept import-free so it can be unit tested.

export interface HuntFlowRow { ClientId?: unknown; Hostname?: unknown; TotalRows?: unknown }

/** Hosts whose hunt flow returned at least one row, without duplicates. */
export function matchedHosts(rows: HuntFlowRow[]): { id: string; hostname: string }[] {
  const seen = new Set<string>();
  const out: { id: string; hostname: string }[] = [];
  for (const r of rows) {
    const id = typeof r.ClientId === 'string' ? r.ClientId : '';
    if (!id || seen.has(id) || !(Number(r.TotalRows ?? 0) > 0)) continue;
    seen.add(id);
    out.push({ id, hostname: typeof r.Hostname === 'string' && r.Hostname ? r.Hostname : id });
  }
  return out;
}
