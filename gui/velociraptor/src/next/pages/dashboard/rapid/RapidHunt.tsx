// Rapid hunt: type a domain, URL or IP and see which machines visited it.
// Starts an urgent hunt of Generic.Detection.RapidHunt on every client
// and streams results in as clients answer.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useHistory, useLocation } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ChevronDown, ChevronRight, Cpu, FileText, Fingerprint, Globe, Radar, Search, User, X } from 'lucide-react';

const KIND_ICON = { web: Globe, hash: Fingerprint, file: FileText, process: Cpu, user: User } as const;
import * as api from '../../../lib/api';
import { useCreateHunt, useHunt, useHunts, useStopHunts } from '../../../lib/queries';
import { parseTable, type Row } from '../../../lib/table';
import type { TableResponse } from '../../../lib/types';
import { timeAgo, toDate, toNum } from '../../../lib/format';
import { Badge, Button, Card, CardHeader, EmptyState, Input, Mono, Select, Switch, Tooltip, cn } from '../../../ui/primitives';
import {
  cleanIndicator, detectKind, groupByHost, kindProblem, parseRapidDescription, RAPID_ARTIFACT, RAPID_KIND_LABEL,
  RAPID_KIND_QUESTION, RAPID_KINDS, RAPID_TAG, rapidDescription, type HostHits, type RapidEntry, type RapidKind,
} from './model';
import { prefillIocSweep } from '../../../lib/prefill';
import { untilStoppedExpiry } from '../../hunts/time';
import { AddToCaseButton } from '../../cases/AddToCaseButton';

type Recent = RapidEntry;

function useRapidResults(huntId: string | undefined, answered: number) {
  return useQuery({
    queryKey: ['rapid-results', huntId, answered],
    placeholderData: keepPreviousData,
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
    staleTime: Infinity,
  });
}

export function RapidHuntPanel({ canHunt }: { canHunt: boolean }) {
  const create = useCreateHunt();
  const [indicator, setIndicator] = useState('');
  const location = useLocation();
  const history = useHistory();
  const inputRef = useRef<HTMLInputElement>(null);
  // ?rapid=<indicator> (from the command palette or a pivot) prefills
  // the box; the analyst still presses "Hunt the fleet".
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const v = params.get('rapid');
    if (v) {
      setIndicator(v);
      params.delete('rapid');
      history.replace({ search: params.toString() });
      inputRef.current?.focus();
      inputRef.current?.scrollIntoView({ block: 'center' });
    }
  }, [location.search, history]);
  const [days, setDays] = useState('30');
  const [eventLogs, setEventLogs] = useState(true);
  const [untilStopped, setUntilStopped] = useState(false);
  const [kindChoice, setKindChoice] = useState<RapidKind | 'auto'>('auto');
  const kind: RapidKind = kindChoice === 'auto' ? detectKind(indicator) : kindChoice;

  // History comes from the server (hunts tagged rapid-hunt), so the whole
  // team sees it, on any computer.
  const { data: hunts = [] } = useHunts(false);
  const recent: Recent[] = useMemo(() => hunts
    .filter(h => (h.tags ?? []).includes(RAPID_TAG))
    .map(h => {
      const p = parseRapidDescription(h.hunt_description ?? '');
      return p ? {
        huntId: h.hunt_id, indicator: p.indicator, kind: p.kind,
        started: toDate(h.create_time)?.getTime() ?? 0, creator: String(h.creator ?? ''),
      } : null;
    })
    .filter((r): r is Recent => !!r)
    .sort((a, b) => b.started - a.started)
    .slice(0, 8), [hunts]);
  const [activeId, setActiveId] = useState<string | null | undefined>(undefined);
  // Until the analyst picks one, show the newest.
  const active = activeId === undefined ? recent[0] ?? null : recent.find(r => r.huntId === activeId) ?? null;
  const pasted = indicator.trim().split(/[\s,;]+/).filter(Boolean);
  const many = pasted.length > 1;
  const problem = indicator.trim() && !many ? kindProblem(indicator, kind) : null;

  const start = async () => {
    const value = cleanIndicator(indicator);
    try {
      const r = await create.mutateAsync({
        hunt_description: rapidDescription(value, kind),
        tags: [RAPID_TAG],
        // One hour unless asked to keep waiting for offline machines.
        expires: untilStopped ? untilStoppedExpiry() : (Date.now() + 3600 * 1000) * 1000,
        start_request: {
          artifacts: [RAPID_ARTIFACT],
          specs: [{
            artifact: RAPID_ARTIFACT,
            parameters: { env: [
              { key: 'Indicator', value },
              { key: 'Kind', value: kind },
              { key: 'DaysBack', value: days },
              { key: 'IncludeEventLogs', value: eventLogs ? 'Y' : 'N' },
            ] },
          }],
          urgent: true,
        },
        state: 2,
      });
      if (!r.flow_id) throw new Error('The hunt was not created.');
      setActiveId(r.flow_id);
      setIndicator('');
      setKindChoice('auto');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Card>
      <CardHeader icon={<Radar className="tw:size-4" />} title="Rapid hunt"
        subtitle="Which machines have seen this? Paste a website, IP, file hash, file name or path, program or user name and every machine checks itself." />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <form className="tw:flex tw:flex-wrap tw:items-center tw:gap-2"
          onSubmit={e => {
            e.preventDefault();
            if (many) { prefillIocSweep(pasted.join('\n')); history.push('/ioc'); return; }
            if (!problem && indicator.trim()) void start();
          }}>
          <div className="tw:relative tw:flex-1 tw:min-w-[260px]">
            <Search className="tw:absolute tw:left-2 tw:top-2 tw:size-4 tw:text-faint" />
            <Input ref={inputRef} value={indicator} onChange={e => setIndicator(e.target.value)} className="tw:pl-8"
              placeholder="evil.example, 203.0.113.7, a SHA256, invoice.js, rclone.exe or CORP\alice" disabled={!canHunt} />
          </div>
          <Select value={kindChoice} onChange={e => setKindChoice(e.target.value as RapidKind | 'auto')} aria-label="Kind of indicator">
            <option value="auto">{indicator.trim() && !many ? `Auto: ${RAPID_KIND_LABEL[kind]}` : 'Auto-detect'}</option>
            {RAPID_KINDS.map(k => <option key={k} value={k}>{RAPID_KIND_LABEL[k]}</option>)}
          </Select>
          <Select value={days} onChange={e => setDays(e.target.value)} aria-label="Look back">
            <option value="1">Last day</option>
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
          </Select>
          <Switch checked={eventLogs} onChange={setEventLogs} label="Event logs" />
          <Tooltip content="Off: the hunt stops after 1 hour. On: machines that come online later still answer, until you stop it.">
            <span><Switch checked={untilStopped} onChange={setUntilStopped} label="Run until stopped" /></span>
          </Tooltip>
          <Button type="submit" variant="primary" icon={<Radar className="tw:size-3.5" />}
            loading={create.isPending} disabled={!canHunt || !indicator.trim() || !!problem}>
            {many ? `IOC sweep for ${pasted.length}…` : 'Hunt the fleet'}
          </Button>
        </form>
        {problem && <div className="tw:text-2xs tw:text-bad">{problem}</div>}
        {many && <div className="tw:text-2xs tw:text-muted">Several indicators: they open in IOC sweep, which hunts for all of them at once.</div>}
        {!many && indicator.trim() && !problem && (kind === 'hash' || kind === 'file') && (
          <div className="tw:text-2xs tw:text-muted">Hashing files under user, temp and ProgramData folders can take a few minutes per machine.</div>
        )}
        {!canHunt && <div className="tw:text-2xs tw:text-muted">You need permission to start hunts.</div>}

        {recent.length > 0 && (
          <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5 tw:text-xs">
            <span className="tw:text-muted">Recent:</span>
            {recent.map(r => (
              <button key={r.huntId} type="button" onClick={() => setActiveId(r.huntId)}
                title={`${RAPID_KIND_LABEL[r.kind]} · started by ${r.creator || 'unknown'} ${timeAgo(r.started)}`}
                className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5',
                  active?.huntId === r.huntId ? 'tw:border-accent tw:bg-accent-soft tw:text-accent' : 'tw:border-line tw:hover:bg-hover')}>
                {r.indicator}
              </button>
            ))}
            <Link to="/hunts" className="tw:text-muted tw:hover:text-fg tw:underline tw:ml-1">All hunts</Link>
          </div>
        )}

        {active && <RapidResults key={active.huntId} entry={active} onClose={() => setActiveId(null)} />}
      </div>
    </Card>
  );
}

function RapidResults({ entry, onClose }: { entry: Recent; onClose: () => void }) {
  const { data: hunt } = useHunt(entry.huntId);
  const stop = useStopHunts();
  const state = String(hunt?.state ?? '');
  const running = state === 'RUNNING' || state === '2';
  const answeredKey = toNum(hunt?.stats?.total_clients_with_results) + toNum(hunt?.stats?.total_clients_with_errors);
  const { data, isLoading } = useRapidResults(entry.huntId, answeredKey);
  const hosts = useMemo(() => groupByHost(data?.rows ?? []), [data]);
  const scheduled = toNum(hunt?.stats?.total_clients_scheduled);
  const done = toNum(hunt?.stats?.total_clients_with_results) + toNum(hunt?.stats?.total_clients_with_errors);
  const answered = Math.min(scheduled, Math.max(done, toNum(hunt?.stats?.total_clients_with_results)));

  return (
    <div className="tw:rounded-md tw:border tw:border-line">
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:px-3 tw:py-2 tw:border-b tw:border-line tw:bg-sunken">
        {(() => { const Icon = KIND_ICON[entry.kind as keyof typeof KIND_ICON] ?? Globe; return <Icon className="tw:size-4 tw:text-accent" />; })()}
        <span className="tw:text-xs tw:text-muted">Who {RAPID_KIND_QUESTION[entry.kind]}</span>
        <Mono className="tw:font-medium">{entry.indicator}</Mono>
        <Badge tone={hosts.length ? 'bad' : 'neutral'}>{hosts.length} machine{hosts.length === 1 ? '' : 's'} matched</Badge>
        <span className="tw:text-2xs tw:text-muted">
          {scheduled ? `${answered} of ${scheduled} machines answered` : 'waiting for machines…'} · started {timeAgo(entry.started)}{entry.creator ? ` by ${entry.creator}` : ''}
          {running ? ' · results update live' : state ? ` · hunt ${state.toLowerCase()}` : ''}
        </span>
        <span className="tw:ml-auto tw:flex tw:items-center tw:gap-2">
          {hosts.length > 0 && (
            <Link to={`/response/quarantine?client=${hosts.slice(0, 100).map(h => h.clientId).join(",")}`}
              className="tw:text-xs tw:font-medium tw:text-bad tw:hover:underline"
              title="Opens Response with these machines selected; pick any action there">
              {hosts.length > 100 ? `Respond to the first 100 of ${hosts.length}` : `Respond to ${hosts.length > 1 ? `all ${hosts.length}` : 'this machine'}`}
            </Link>
          )}
                    <AddToCaseButton size="sm" label="Add to case" suggestedTitle={`Rapid hunt: ${entry.indicator}`}
            item={{ kind: 'hunt', ref: entry.huntId,
              label: `Rapid hunt for ${entry.indicator}: ${hosts.length} machine${hosts.length === 1 ? '' : 's'} matched (${hosts.map(h => h.hostname).slice(0, 10).join(', ')}${hosts.length > 10 ? ', …' : ''})` }} />
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
          {running ? 'Machines answer as they come online; matches appear here.' : 'None of the machines that answered found a match.'}
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
