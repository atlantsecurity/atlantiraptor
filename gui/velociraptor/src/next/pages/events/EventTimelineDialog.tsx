// Several event artifacts on one timeline: a lane per artifact showing
// when its events happened, and one merged table, newest first.
import { useMemo, useState } from 'react';
import { useQueries } from '@tanstack/react-query';
import { GanttChart } from 'lucide-react';
import * as api from '../../lib/api';
import { parseTable } from '../../lib/table';
import type { TableResponse } from '../../lib/types';
import { fmtNum, fmtTime } from '../../lib/format';
import { Badge, Dialog, Segmented, Skeleton, cn } from '../../ui/primitives';
import { DataTable } from '../../ui/DataTable';
import { mergeTimeline, rowSeconds } from './eventTimeline';
import { useEventArtifacts } from '../../lib/queries';

const RANGES = [
  { value: '3600', label: '1 hour' },
  { value: '86400', label: '24 hours' },
  { value: '604800', label: '7 days' },
];
const ROWS_PER_ARTIFACT = 2000;
const LANE_COLORS = ['tw:bg-accent', 'tw:bg-ok', 'tw:bg-warn', 'tw:bg-bad', 'tw:bg-info', 'tw:bg-fg'];

export function EventTimelineDialog({ clientId, initial, onClose }: {
  clientId: string; initial?: string; onClose: () => void;
}) {
  const { data: available } = useEventArtifacts(clientId);
  const artifacts = useMemo(() => (available ?? []).map(a => a.artifact).sort(), [available]);
  const [selected, setSelected] = useState<string[]>(() => (initial ? [initial] : []));
  const [range, setRange] = useState('86400');
  // Fixed when the range changes, so the query keys stay stable.
  const [end, setEnd] = useState(() => Math.floor(Date.now() / 1000));
  const start = end - Number(range);
  const type = clientId === 'server' ? 'SERVER_EVENT' : 'CLIENT_EVENT';

  const results = useQueries({
    queries: selected.map(artifact => ({
      queryKey: ['event-timeline', clientId, artifact, start, end],
      queryFn: async ({ signal }: { signal: AbortSignal }) => {
        try {
          return parseTable(await api.get<TableResponse>('v1/GetTable', {
            client_id: clientId, artifact, type, start_time: start, end_time: end, rows: ROWS_PER_ARTIFACT,
          }, signal)).rows;
        } catch (e) {
          if (e instanceof Error && /not found/i.test(e.message)) return [];
          throw e;
        }
      },
    })),
  });
  const loading = results.some(r => r.isLoading);
  const byArtifact = useMemo(() => Object.fromEntries(selected.map((a, i) => [a, (results[i]?.data ?? []) as Record<string, unknown>[]])),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [selected, ...results.map(r => r.data)]);
  const events = useMemo(() => mergeTimeline(byArtifact), [byArtifact]);
  const capped = selected.filter(a => byArtifact[a].length >= ROWS_PER_ARTIFACT);
  const rows = useMemo(() => events.map(e => ({ Time: e.ts, Artifact: e.artifact, Details: e.summary, _row: e.row })), [events]);

  const toggle = (a: string) => setSelected(s => (s.includes(a) ? s.filter(x => x !== a) : [...s, a]));

  return (
    <Dialog open onOpenChange={v => !v && onClose()} width={1240}
      title={<span className="tw:flex tw:items-center tw:gap-2"><GanttChart className="tw:size-4 tw:text-accent" />Event timeline</span>}
      description="Pick event artifacts to see their events side by side.">
      <div className="tw:space-y-3">
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <Segmented value={range} onChange={v => { setRange(v); setEnd(Math.floor(Date.now() / 1000)); }} options={RANGES} />
          <span className="tw:text-2xs tw:text-muted">{fmtTime(start)} to {fmtTime(end)}</span>
        </div>
        <div className="tw:flex tw:flex-wrap tw:gap-1.5">
          {artifacts.map(a => {
            const i = selected.indexOf(a);
            return (
              <button key={a} type="button" onClick={() => toggle(a)}
                className={cn('tw:inline-flex tw:items-center tw:gap-1.5 tw:rounded-md tw:border tw:px-2 tw:py-0.5 tw:font-mono tw:text-[11px]',
                  i >= 0 ? 'tw:border-accent tw:bg-accent-soft' : 'tw:border-line tw:text-muted tw:hover:text-fg')}>
                {i >= 0 && <span className={cn('tw:size-2 tw:rounded-full', LANE_COLORS[i % LANE_COLORS.length])} />}
                {a}
              </button>
            );
          })}
          {artifacts.length === 0 && <span className="tw:text-xs tw:text-faint">No event artifact has data yet.</span>}
        </div>

        <div className="tw:rounded-lg tw:border tw:border-line tw:p-3 tw:space-y-2">
          {selected.length === 0 && <div className="tw:text-xs tw:text-faint">Pick at least one artifact.</div>}
          {selected.map((a, i) => (
            <div key={a} className="tw:flex tw:items-center tw:gap-3">
              <span className="tw:w-64 tw:shrink-0 tw:truncate tw:font-mono tw:text-[11px]" title={a}>{a}</span>
              <div className="tw:relative tw:h-4 tw:flex-1 tw:rounded tw:bg-sunken">
                {results[i]?.isLoading ? <Skeleton className="tw:h-4" /> : byArtifact[a].map((r, j) => {
                  const ts = rowSeconds(r);
                  if (!ts || ts < start || ts > end) return null;
                  return <span key={j} className={cn('tw:absolute tw:top-0.5 tw:h-3 tw:w-0.5 tw:rounded-full tw:opacity-70', LANE_COLORS[i % LANE_COLORS.length])}
                    style={{ left: `${((ts - start) / (end - start)) * 100}%` }} />;
                })}
              </div>
              <Badge tone="neutral">{fmtNum(byArtifact[a].length)}</Badge>
            </div>
          ))}
          {capped.length > 0 && (
            <div className="tw:text-2xs tw:text-warn">Showing the first {fmtNum(ROWS_PER_ARTIFACT)} events of {capped.join(', ')}; pick a shorter range to see all.</div>
          )}
        </div>

        <div className="tw:h-[420px] tw:flex tw:flex-col">
          <DataTable rows={rows} columns={['Time', 'Artifact', 'Details']} loading={loading} dense
            renderers={{ Time: v => <span className="tw:whitespace-nowrap">{fmtTime(v as number)}</span> }}
            columnWidths={{ Time: 170, Artifact: 260 }} exportName="event-timeline"
            empty={selected.length ? 'No events in this range.' : 'Pick an artifact.'} />
        </div>
      </div>
    </Dialog>
  );
}
