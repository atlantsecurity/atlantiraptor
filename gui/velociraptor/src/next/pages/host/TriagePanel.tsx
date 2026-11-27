// Full triage on the host page: one button collects the standard set,
// then the findings worth a look and an activity timeline appear here,
// without leaving the page.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ChevronDown, ChevronRight, ListChecks, ScanEye } from 'lucide-react';
import * as api from '../../lib/api';
import { useClientFlowList, useFlow } from '../../lib/queries';
import { parseTable } from '../../lib/table';
import type { ApiClient, TableResponse } from '../../lib/types';
import { fmtNum, fmtTime, timeAgo } from '../../lib/format';
import { FULL_TRIAGE, osOf, startFullTriage } from '../../lib/triage';
import { Badge, Button, Card, CardHeader, EmptyState, Skeleton, cn } from '../../ui/primitives';
import { DataTable } from '../../ui/DataTable';
import { findings, timeline, type Finding, type Row } from './findings';

const ROWS_PER_SOURCE = 5000;

function isTriageFlow(arts: string[], os: ReturnType<typeof osOf>): boolean {
  const want = FULL_TRIAGE[os];
  return arts.length >= Math.min(4, want.length) && arts.filter(a => want.includes(a)).length >= Math.min(4, want.length);
}

export function TriagePanel({ clientId, client, canCollect }: { clientId: string; client: ApiClient; canCollect: boolean }) {
  const os = osOf(client);
  const flows = useClientFlowList(clientId, 50);
  const latest = useMemo(() => (flows.data?.rows ?? [])
    .find(r => isTriageFlow((r.Artifacts as string[] | undefined) ?? [], os)), [flows.data, os]);
  const flowId = latest ? String(latest.FlowId) : undefined;
  const { data: flow } = useFlow(clientId, flowId);
  const state = String(flow?.context?.state ?? latest?.State ?? '');
  const running = state === 'RUNNING' || state === 'IN_PROGRESS' || state === 'WAITING';
  const sources = flow?.context?.artifacts_with_results ?? [];
  const [starting, setStarting] = useState(false);
  const [view, setView] = useState<'findings' | 'timeline'>('findings');

  const results = useQuery({
    queryKey: ['triage-results', clientId, flowId, sources.join(','), state],
    enabled: !!flowId && sources.length > 0,
    staleTime: Infinity,
    queryFn: async ({ signal }) => {
      const out: Record<string, Row[]> = {};
      await Promise.all(sources.map(async s => {
        try {
          const t = parseTable(await api.get<TableResponse>('v1/GetTable', {
            client_id: clientId, flow_id: flowId, artifact: s, start_row: 0, rows: ROWS_PER_SOURCE,
          }, signal));
          out[s] = t.rows;
        } catch {
          out[s] = [];
        }
      }));
      return out;
    },
  });
  const found = useMemo(() => (results.data ? findings(results.data) : []), [results.data]);
  const events = useMemo(() => (results.data ? timeline(results.data) : []), [results.data]);

  const start = async () => {
    setStarting(true);
    try {
      await startFullTriage(clientId, client);
      toast.success('Full triage started. Results appear here as they arrive.');
      await flows.refetch();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setStarting(false);
    }
  };

  return (
    <Card className="tw:xl:col-span-3">
      <CardHeader icon={<ScanEye className="tw:size-4" />} title="Full triage"
        subtitle={latest
          ? <>Last run {timeAgo(latest.Created as number)}{running ? ' · collecting now…' : ''} · <Link className="tw:text-accent tw:hover:underline" to={`/collected/${clientId}/${flowId}`}>all results</Link></>
          : 'Processes, network connections, persistence, users and execution history, in one collection.'}
        actions={<Button variant="primary" size="sm" icon={<ListChecks className="tw:size-3.5" />} loading={starting || running}
          disabled={!canCollect} onClick={start}>{latest ? 'Run again' : 'Run full triage'}</Button>} />
      {!latest ? (
        <div className="tw:px-4 tw:pb-4 tw:text-xs tw:text-muted">
          Runs {FULL_TRIAGE[os].length} artifacts as one urgent collection. Findings worth a look and an activity timeline show up here.
        </div>
      ) : (
        <div className="tw:border-t tw:border-line">
          <div className="tw:flex tw:items-center tw:gap-1 tw:px-3 tw:py-2 tw:border-b tw:border-line">
            {(['findings', 'timeline'] as const).map(v => (
              <button key={v} type="button" onClick={() => setView(v)}
                className={cn('tw:rounded-md tw:px-2.5 tw:py-1 tw:text-xs tw:font-medium',
                  view === v ? 'tw:bg-active tw:text-fg' : 'tw:text-muted tw:hover:bg-hover')}>
                {v === 'findings' ? `Worth a look${found.length ? ` (${found.length})` : ''}` : `Activity timeline${events.length ? ` (${fmtNum(events.length)})` : ''}`}
              </button>
            ))}
            {running && <span className="tw:ml-auto tw:text-2xs tw:text-muted">{sources.length} of {FULL_TRIAGE[os].length} artifacts returned so far</span>}
          </div>
          {results.isLoading || (!results.data && sources.length > 0) ? (
            <div className="tw:p-4 tw:space-y-2">{[0, 1, 2].map(i => <Skeleton key={i} />)}</div>
          ) : view === 'findings' ? (
            found.length === 0 ? (
              <EmptyState icon={<ScanEye />} title={running ? 'Nothing flagged so far' : 'Nothing flagged'}>
                No process, connection or persistence entry matched the checks. Review the full results for anything specific.
              </EmptyState>
            ) : (
              <div className="tw:divide-y tw:divide-line">{found.map(f => <FindingRow key={f.id} f={f} link={`/collected/${clientId}/${flowId}`} />)}</div>
            )
          ) : (
            <div className="tw:h-[420px] tw:flex tw:flex-col">
              <DataTable rows={events.map(e => ({ Time: e.time, What: e.what, Detail: e.detail, Source: e.source }))}
                columns={['Time', 'What', 'Detail', 'Source']} columnWidths={{ Time: 170, What: 150, Detail: 620, Source: 260 }}
                renderers={{ Time: v => <span className="rx-num tw:text-muted">{fmtTime(new Date(v as number))}</span> }}
                storageKey="host-timeline" exportName={`${clientId}-timeline`} dense />
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function FindingRow({ f, link }: { f: Finding; link: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="tw:flex tw:w-full tw:items-center tw:gap-2 tw:px-4 tw:py-2.5 tw:text-left tw:hover:bg-hover">
        {open ? <ChevronDown className="tw:size-3.5 tw:text-faint" /> : <ChevronRight className="tw:size-3.5 tw:text-faint" />}
        <Badge tone={f.tone} dot>{f.tone === 'bad' ? 'Review' : f.tone === 'warn' ? 'Check' : 'Note'}</Badge>
        <span className="tw:text-[13px] tw:font-medium">{f.title}</span>
        <span className="tw:ml-auto tw:font-mono tw:text-2xs tw:text-faint">{f.source}</span>
      </button>
      {open && (
        <div className="tw:px-4 tw:pb-3 tw:pl-10 tw:space-y-1.5">
          <div className="tw:text-2xs tw:text-muted">{f.why}</div>
          {/* Endpoint values: plain text only. */}
          {f.rows.slice(0, 20).map((r, i) => (
            <div key={i} className="tw:font-mono tw:text-[11.5px] tw:break-all">{f.summary(r)}</div>
          ))}
          {f.rows.length > 20 && <div className="tw:text-2xs tw:text-muted">…and {f.rows.length - 20} more.</div>}
          <Link to={link} className="tw:text-xs tw:text-accent tw:hover:underline">Open the collection</Link>
        </div>
      )}
    </div>
  );
}
