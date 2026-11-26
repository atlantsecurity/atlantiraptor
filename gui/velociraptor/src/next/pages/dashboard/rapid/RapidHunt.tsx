// Rapid hunt: type a domain, URL or IP and see which machines visited it.
// Starts an urgent hunt of Generic.Detection.RapidHunt on every client
// and streams results in as clients answer.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ChevronDown, ChevronRight, Globe, Radar, Search, X } from 'lucide-react';
import * as api from '../../../lib/api';
import { useCreateHunt, useHunt, useStopHunts } from '../../../lib/queries';
import { parseTable, type Row } from '../../../lib/table';
import type { TableResponse } from '../../../lib/types';
import { timeAgo, toNum } from '../../../lib/format';
import { Badge, Button, Card, CardHeader, EmptyState, Input, Mono, Select, Switch, cn } from '../../../ui/primitives';
import { groupByHost, indicatorProblem, RAPID_ARTIFACT, type HostHits } from './model';

const STORE_KEY = 'atl.rapidhunts';

interface Recent { huntId: string; indicator: string; started: number }

function loadRecent(): Recent[] {
  try {
    const v = JSON.parse(localStorage.getItem(STORE_KEY) || '[]') as Recent[];
    return Array.isArray(v) ? v.slice(0, 6) : [];
  } catch {
    return [];
  }
}

function saveRecent(r: Recent[]) {
  localStorage.setItem(STORE_KEY, JSON.stringify(r.slice(0, 6)));
}

function useRapidResults(huntId: string | undefined, live: boolean) {
  return useQuery({
    queryKey: ['rapid-results', huntId],
    enabled: !!huntId,
    queryFn: async ({ signal }) => {
      try {
        return parseTable(await api.get<TableResponse>('v1/GetHuntResults',
          { hunt_id: huntId, artifact: RAPID_ARTIFACT, offset: 0, count: 5000 }, signal));
      } catch (e) {
        if (e instanceof Error && /not found/i.test(e.message)) return { columns: [], rows: [] as Row[], total: 0 };
        throw e;
      }
    },
    refetchInterval: live ? 2_000 : false,
  });
}

export function RapidHuntPanel({ canHunt }: { canHunt: boolean }) {
  const create = useCreateHunt();
  const [indicator, setIndicator] = useState('');
  const [days, setDays] = useState('30');
  const [eventLogs, setEventLogs] = useState(true);
  const [recent, setRecent] = useState<Recent[]>(loadRecent);
  const [active, setActive] = useState<Recent | null>(() => loadRecent()[0] ?? null);
  const problem = indicator.trim() ? indicatorProblem(indicator) : null;

  const start = async () => {
    const value = indicator.trim();
    try {
      const r = await create.mutateAsync({
        hunt_description: `Rapid hunt: ${value}`,
        tags: ['rapid-hunt'],
        // Clients that come online within a day still answer.
        expires: (Date.now() + 24 * 3600 * 1000) * 1000,
        start_request: {
          artifacts: [RAPID_ARTIFACT],
          specs: [{
            artifact: RAPID_ARTIFACT,
            parameters: { env: [
              { key: 'Indicator', value },
              { key: 'DaysBack', value: days },
              { key: 'IncludeEventLogs', value: eventLogs ? 'Y' : 'N' },
            ] },
          }],
          urgent: true,
        },
        state: 2,
      });
      if (!r.flow_id) throw new Error('The hunt was not created.');
      const entry = { huntId: r.flow_id, indicator: value, started: Date.now() };
      const next = [entry, ...recent.filter(x => x.huntId !== entry.huntId)];
      setRecent(next);
      saveRecent(next);
      setActive(entry);
      setIndicator('');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Card>
      <CardHeader icon={<Radar className="tw:size-4" />} title="Rapid hunt"
        subtitle="Who visited a website or IP? Searches browser history, DNS cache, live connections and Sysmon on every machine." />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <form className="tw:flex tw:flex-wrap tw:items-center tw:gap-2"
          onSubmit={e => { e.preventDefault(); if (!problem && indicator.trim()) void start(); }}>
          <div className="tw:relative tw:flex-1 tw:min-w-[260px]">
            <Search className="tw:absolute tw:left-2 tw:top-2 tw:size-4 tw:text-faint" />
            <Input value={indicator} onChange={e => setIndicator(e.target.value)} className="tw:pl-8"
              placeholder="example.com, https://evil.example/path or 203.0.113.7" disabled={!canHunt} />
          </div>
          <Select value={days} onChange={e => setDays(e.target.value)} aria-label="Look back">
            <option value="1">Last day</option>
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
          </Select>
          <Switch checked={eventLogs} onChange={setEventLogs} label="Event logs" />
          <Button type="submit" variant="primary" icon={<Radar className="tw:size-3.5" />}
            loading={create.isPending} disabled={!canHunt || !indicator.trim() || !!problem}>Hunt the fleet</Button>
        </form>
        {problem && <div className="tw:text-2xs tw:text-bad">{problem}</div>}
        {!canHunt && <div className="tw:text-2xs tw:text-muted">You need permission to start hunts.</div>}

        {recent.length > 0 && (
          <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5 tw:text-xs">
            <span className="tw:text-muted">Recent:</span>
            {recent.map(r => (
              <button key={r.huntId} type="button" onClick={() => setActive(r)}
                className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5',
                  active?.huntId === r.huntId ? 'tw:border-accent tw:bg-accent-soft tw:text-accent' : 'tw:border-line tw:hover:bg-hover')}>
                {r.indicator}
              </button>
            ))}
            <button type="button" className="tw:text-muted tw:hover:text-fg tw:underline tw:ml-1"
              onClick={() => { setRecent([]); saveRecent([]); setActive(null); }}>Clear</button>
          </div>
        )}

        {active && <RapidResults key={active.huntId} entry={active} onClose={() => setActive(null)} />}
      </div>
    </Card>
  );
}

function RapidResults({ entry, onClose }: { entry: Recent; onClose: () => void }) {
  const { data: hunt } = useHunt(entry.huntId);
  const stop = useStopHunts();
  const state = String(hunt?.state ?? '');
  const running = state === 'RUNNING' || state === '2';
  const { data, isLoading } = useRapidResults(entry.huntId, running);
  const hosts = useMemo(() => groupByHost(data?.rows ?? []), [data]);
  const scheduled = toNum(hunt?.stats?.total_clients_scheduled);
  const done = toNum(hunt?.stats?.total_clients_with_results) + toNum(hunt?.stats?.total_clients_with_errors);
  const answered = Math.min(scheduled, Math.max(done, toNum(hunt?.stats?.total_clients_with_results)));

  return (
    <div className="tw:rounded-md tw:border tw:border-line">
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:px-3 tw:py-2 tw:border-b tw:border-line tw:bg-sunken">
        <Globe className="tw:size-4 tw:text-accent" />
        <Mono className="tw:font-medium">{entry.indicator}</Mono>
        <Badge tone={hosts.length ? 'bad' : 'neutral'}>{hosts.length} machine{hosts.length === 1 ? '' : 's'} matched</Badge>
        <span className="tw:text-2xs tw:text-muted">
          {scheduled ? `${answered} of ${scheduled} machines answered` : 'waiting for machines…'} · started {timeAgo(entry.started * 1000)}
          {running ? ' · results update live' : state ? ` · hunt ${state.toLowerCase()}` : ''}
        </span>
        <span className="tw:ml-auto tw:flex tw:items-center tw:gap-2">
          {hosts.length > 0 && (
            <Link to={`/response/quarantine?client=${hosts.slice(0, 100).map(h => h.clientId).join(",")}`}
              className="tw:text-xs tw:font-medium tw:text-bad tw:hover:underline"
              title="Opens Response with these machines selected; pick any action there">
              Respond to {hosts.length > 1 ? `all ${Math.min(hosts.length, 100)}` : "this machine"}
            </Link>
          )}
                    <Link to={`/hunts/${entry.huntId}`} className="tw:text-xs tw:text-accent tw:hover:underline">Open hunt</Link>
          {running && (
            <button type="button" className="tw:text-xs tw:text-muted tw:hover:text-fg tw:underline"
              onClick={() => stop.mutate([entry.huntId])}>Stop</button>
          )}
          <button type="button" aria-label="Close results" className="tw:text-muted tw:hover:text-fg" onClick={onClose}><X className="tw:size-4" /></button>
        </span>
      </div>
      {isLoading && <div className="tw:px-3 tw:py-3 tw:text-xs tw:text-muted">Loading results…</div>}
      {!isLoading && hosts.length === 0 && (
        <EmptyState icon={<Radar />} title={running ? 'No matches yet' : 'No machine visited it'}>
          {running ? 'Machines answer as they come online; matches appear here.' : 'No browser history, DNS cache, connection or Sysmon record matched.'}
        </EmptyState>
      )}
      <div className="tw:divide-y tw:divide-line">
        {hosts.map(h => <HostRow key={h.clientId} host={h} />)}
      </div>
    </div>
  );
}

function HostRow({ host }: { host: HostHits }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="tw:flex tw:w-full tw:items-center tw:gap-2 tw:px-3 tw:py-2 tw:text-left tw:text-xs tw:hover:bg-hover">
        {open ? <ChevronDown className="tw:size-3.5" /> : <ChevronRight className="tw:size-3.5" />}
        <span className="tw:font-medium tw:text-[13px]">{host.hostname}</span>
        <span className="tw:font-mono tw:text-[10px] tw:text-faint">{host.clientId}</span>
        <span className="tw:flex tw:flex-wrap tw:gap-1">
          {host.sources.map(s => <Badge key={s} tone="info">{s}</Badge>)}
        </span>
        {host.users.length > 0 && <span className="tw:text-muted">users: {host.users.join(', ')}</span>}
        <span className="tw:ml-auto tw:text-muted">{host.hits.length} hit{host.hits.length === 1 ? '' : 's'}{host.last ? ` · last ${timeAgo(host.last)}` : ''}</span>
        <Link to={`/host/${host.clientId}`} onClick={e => e.stopPropagation()} className="tw:text-accent tw:hover:underline">Host</Link>
        <Link to={`/response/quarantine?client=${host.clientId}`} onClick={e => e.stopPropagation()} className="tw:text-bad tw:hover:underline">Respond</Link>
      </button>
      {open && (
        <div className="tw:overflow-x-auto tw:bg-canvas/50">
          <table className="tw:w-full tw:text-xs">
            <thead className="tw:text-muted tw:text-left">
              <tr>{['When', 'Source', 'User', 'Process', 'Match', 'Detail'].map(c => <th key={c} className="tw:px-3 tw:py-1 tw:font-medium">{c}</th>)}</tr>
            </thead>
            <tbody>
              {host.hits.map((r, i) => (
                <tr key={i} className="tw:border-t tw:border-line tw:align-top">
                  <td className="tw:px-3 tw:py-1 tw:whitespace-nowrap">{r.time ? new Date(r.time).toLocaleString() : ''}</td>
                  <td className="tw:px-3 tw:py-1 tw:whitespace-nowrap">{r.source}</td>
                  <td className="tw:px-3 tw:py-1">{r.user}</td>
                  <td className="tw:px-3 tw:py-1">{r.process}</td>
                  <td className="tw:px-3 tw:py-1 tw:break-all"><Mono className="tw:text-[11px]">{r.match}</Mono></td>
                  <td className="tw:px-3 tw:py-1 tw:text-muted tw:break-all">{r.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
