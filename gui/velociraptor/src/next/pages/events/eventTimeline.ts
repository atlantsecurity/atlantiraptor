// Merges the rows of several event artifacts into one time-ordered
// timeline. Kept free of app imports so it can be unit tested.

export interface TimelineEvent {
  ts: number; // seconds
  artifact: string;
  summary: string;
  row: Record<string, unknown>;
}

const TIME_FIELDS = ['_ts', 'Timestamp', 'EventTime', 'Time', 'client_time'];
const SKIP = new Set([...TIME_FIELDS, 'ClientId', '_Source']);

/** Seconds since the epoch from a row's time field (s, ms, µs, ns or ISO). */
export function rowSeconds(row: Record<string, unknown>): number {
  for (const f of TIME_FIELDS) {
    const v = row[f];
    if (v === undefined || v === null || v === '') continue;
    if (typeof v === 'string' && !/^\d+(\.\d+)?$/.test(v)) {
      const t = Date.parse(v);
      if (!Number.isNaN(t)) return Math.floor(t / 1000);
      continue;
    }
    let n = Number(v);
    if (!n) continue;
    while (n > 1e11) n /= 1000;
    return Math.floor(n);
  }
  return 0;
}

/** A one-line description: the first few non-empty fields. */
export function summarize(row: Record<string, unknown>, max = 4): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(row)) {
    if (SKIP.has(k) || v === null || v === undefined || v === '') continue;
    const text = typeof v === 'object' ? JSON.stringify(v) : String(v);
    parts.push(`${k}: ${text.length > 80 ? `${text.slice(0, 77)}…` : text}`);
    if (parts.length >= max) break;
  }
  return parts.join(' · ');
}

/** Newest first. Rows without a time sort last. */
export function mergeTimeline(byArtifact: Record<string, Record<string, unknown>[]>): TimelineEvent[] {
  const out: TimelineEvent[] = [];
  for (const [artifact, rows] of Object.entries(byArtifact)) {
    for (const row of rows) out.push({ ts: rowSeconds(row), artifact, summary: summarize(row), row });
  }
  return out.sort((a, b) => b.ts - a.ts || a.artifact.localeCompare(b.artifact));
}
