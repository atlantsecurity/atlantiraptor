// How the Full triage panel reads a collection's results for its checks.
// Each artifact is read once, on its own, as soon as its part of the
// collection has finished, so the first findings show up while the rest
// load, and nothing is downloaded twice. Only the columns the checks,
// timeline, indicators and AI context use are asked for: Prefetch's
// FilesAccessed lists or Amcache's ids are most of the bytes and no
// check reads them. Artifacts no check reads come back as a row count.
// Pure, so it can be unit tested.
import { artifactOf } from './findings.ts';

export const ROWS_PER_SOURCE = 5000;

export interface SourcePlan {
  rows: number;          // rows to fetch (1 = count only)
  columns?: string[];    // undefined = every column
  countOnly?: boolean;
}

const PLANS: [RegExp, SourcePlan][] = [
  // Shown as counts in the summary; no check, timeline or indicator reads the rows.
  [/\.(AppCompatCache|UserAssist|Users)$/, { rows: 1, countOnly: true }],
  [/\.Prefetch$/, { rows: ROWS_PER_SOURCE, columns: ['Executable', 'ExecutablePath', 'ExecutableDosPath', 'LastRunTimes', 'RunCount', 'Hash'] }],
  [/\.Amcache$/, { rows: ROWS_PER_SOURCE, columns: ['FullPath', 'SHA1', 'Name', 'Publisher', 'LastModified'] }],
  [/^Windows\.System\.Pslist$/, {
    rows: ROWS_PER_SOURCE,
    columns: ['Pid', 'Ppid', 'Name', 'Username', 'Exe', 'CommandLine', 'CreateTime', 'Hash', 'Authenticode', 'Deleted'],
  }],
];

export function planFor(source: string): SourcePlan {
  const art = artifactOf(source);
  for (const [re, plan] of PLANS) if (re.test(art)) return plan;
  return { rows: ROWS_PER_SOURCE };
}

export interface QueryStat { status?: string; names_with_response?: string[] }

/**
 * Whether this source's part of the collection is complete, so its rows
 * will not change and can be read once. While the collection runs, a
 * source whose query is still running is read later.
 */
export function sourceDone(source: string, running: boolean, stats: QueryStat[] | undefined): boolean {
  if (!running) return true;
  const art = artifactOf(source);
  const stat = (stats ?? []).find(q => (q.names_with_response ?? []).some(n => n === source || artifactOf(n) === art));
  // OK is the zero value, so a finished query often has no status at all;
  // a query still running reports PROGRESS.
  return !!stat && stat.status !== 'PROGRESS' && stat.status !== 'RUNNING';
}
