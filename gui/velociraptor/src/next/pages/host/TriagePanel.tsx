// Full triage on the host page: one button collects the standard set,
// then the findings worth a look and an activity timeline appear here,
// without leaving the page.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ChevronDown, ChevronRight, Crosshair, ListChecks, ScanEye } from 'lucide-react';
import * as api from '../../lib/api';
import { useClientFlowList, useFlow } from '../../lib/queries';
import { parseTable } from '../../lib/table';
import type { ApiClient, TableResponse } from '../../lib/types';
import { fmtNum, fmtTime, timeAgo } from '../../lib/format';
import { FULL_TRIAGE, osOf, startFullTriage } from '../../lib/triage';
import { Badge, Button, Card, CardHeader, CopyButton, EmptyState, Skeleton, cn } from '../../ui/primitives';
import { DataTable } from '../../ui/DataTable';
import { findings, timeline, type Finding, type Row } from './findings';
import { AI_TASK, IOC_LABELS, aiContext, areas, extractIocs, headline, iocSweepText, type Area, type FoundIoc } from './triageSummary';
import { AiTriageButton } from '../ai/AiTriage';
import { clip } from '../ai/context';
import { prefillIocSweep } from '../../lib/prefill';

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
  const [view, setView] = useState<'summary' | 'findings' | 'timeline'>('summary');

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
  const iocs = useMemo(() => (results.data ? extractIocs(results.data, found) : []), [results.data, found]);
  const byArea = useMemo(() => (results.data ? areas(results.data, found) : []), [results.data, found]);
  const host = client.os_info?.fqdn || client.os_info?.hostname || clientId;

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
        actions={<div className="tw:flex tw:gap-1.5">
          {results.data && !running && <AiTriageButton task={AI_TASK}
            getContext={async () => clip(aiContext(host, clientId, flowId ?? '', results.data!, found, iocs))} />}
          <Button variant="primary" size="sm" icon={<ListChecks className="tw:size-3.5" />} loading={starting || running}
          disabled={!canCollect} onClick={start}>{latest ? 'Run again' : 'Run full triage'}</Button></div>} />
      {!latest ? (
        <div className="tw:px-4 tw:pb-4 tw:text-xs tw:text-muted">
          Runs {FULL_TRIAGE[os].length} artifacts as one urgent collection. Findings worth a look and an activity timeline show up here.
        </div>
      ) : (
        <div className="tw:border-t tw:border-line">
          <div className="tw:flex tw:items-center tw:gap-1 tw:px-3 tw:py-2 tw:border-b tw:border-line">
            {(['summary', 'findings', 'timeline'] as const).map(v => (
              <button key={v} type="button" onClick={() => setView(v)}
                className={cn('tw:rounded-md tw:px-2.5 tw:py-1 tw:text-xs tw:font-medium',
                  view === v ? 'tw:bg-active tw:text-fg' : 'tw:text-muted tw:hover:bg-hover')}>
                {v === 'summary' ? 'Summary' : v === 'findings' ? `Worth a look${found.length ? ` (${found.length})` : ''}` : `Activity timeline${events.length ? ` (${fmtNum(events.length)})` : ''}`}
              </button>
            ))}
            {running && <span className="tw:ml-auto tw:text-2xs tw:text-muted">{sources.length} of {FULL_TRIAGE[os].length} artifacts returned so far</span>}
          </div>
          {results.isLoading || (!results.data && sources.length > 0) ? (
            <div className="tw:p-4 tw:space-y-2">{[0, 1, 2].map(i => <Skeleton key={i} />)}</div>
          ) : view === 'summary' ? (
            <Summary areas={byArea} found={found} iocs={iocs} running={running} onOpen={() => setView('findings')} />
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

function Summary({ areas, found, iocs, running, onOpen }: {
  areas: Area[]; found: Finding[]; iocs: FoundIoc[]; running: boolean; onOpen: () => void;
}) {
  const head = headline(found, iocs);
  const sweep = iocSweepText(iocs);
  return (
    <div className="tw:p-4 tw:space-y-4">
      <div className={cn('tw:rounded-md tw:border tw:px-3 tw:py-2 tw:text-[13px]',
        head.tone === 'bad' ? 'tw:border-bad/40 tw:bg-bad/5' : head.tone === 'warn' ? 'tw:border-warn/40 tw:bg-warn/5' : 'tw:border-line')}>
        <span className="tw:font-medium">{head.text}</span>
        {running && <span className="tw:text-muted"> Still collecting, so this may change.</span>}
        {found.length > 0 && <button type="button" className="tw:ml-2 tw:text-xs tw:text-accent tw:hover:underline" onClick={onOpen}>See what was flagged</button>}
      </div>
      <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:lg:grid-cols-3 tw:gap-2">
        {areas.map(a => (
          <div key={a.id} className="tw:rounded-md tw:border tw:border-line tw:px-3 tw:py-2">
            <div className="tw:flex tw:items-center tw:gap-2">
              <span className="tw:text-[13px] tw:font-medium">{a.label}</span>
              {a.flagged > 0 && <Badge tone={a.findings.some(f => f.tone === 'bad') ? 'bad' : a.findings.some(f => f.tone === 'warn') ? 'warn' : 'info'} dot>{a.flagged} flagged</Badge>}
              <span className="tw:ml-auto rx-num tw:text-xs tw:text-muted">{fmtNum(a.rows)} rows</span>
            </div>
            <div className="tw:mt-1 tw:space-y-0.5">
              {a.findings.length
                ? a.findings.map(f => <div key={f.id} className="tw:text-2xs tw:text-muted">{f.title}</div>)
                : <div className="tw:text-2xs tw:text-faint">Nothing flagged in {a.sources.length} artifact{a.sources.length === 1 ? '' : 's'}.</div>}
            </div>
          </div>
        ))}
      </div>
      <div>
        <div className="tw:flex tw:items-center tw:gap-2 tw:mb-1.5">
          <Crosshair className="tw:size-3.5 tw:text-faint" />
          <span className="tw:text-[13px] tw:font-medium">Indicators found{iocs.length ? ` (${iocs.length})` : ''}</span>
          <span className="tw:text-2xs tw:text-faint">Pulled out by fixed rules, no AI: public IPs, URLs, suspicious commands, and paths and hashes of flagged files.</span>
          {sweep && <div className="tw:ml-auto tw:flex tw:items-center tw:gap-2">
            <CopyButton text={sweep} />
            <Link to="/ioc" onClick={() => prefillIocSweep(sweep)} className="tw:text-xs tw:text-accent tw:hover:underline">Sweep the fleet</Link>
          </div>}
        </div>
        {iocs.length === 0 ? (
          <div className="tw:text-xs tw:text-muted">None found.</div>
        ) : (
          <div className="tw:h-[300px] tw:flex tw:flex-col">
            <DataTable rows={iocs.map(i => ({ Type: IOC_LABELS[i.kind], Value: i.value, Context: i.context, Seen: i.count, Source: i.source }))}
              columns={['Type', 'Value', 'Context', 'Seen', 'Source']} columnWidths={{ Type: 160, Value: 420, Context: 240, Seen: 70, Source: 240 }}
              storageKey="host-triage-iocs" exportName="triage-indicators" dense />
          </div>
        )}
      </div>
    </div>
  );
}
