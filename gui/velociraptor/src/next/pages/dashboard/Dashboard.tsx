import React, { useMemo, useState } from 'react';
import { Link, useHistory } from 'react-router-dom';
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis,
} from 'recharts';
import {
  Monitor, Wifi, Crosshair, Server, Cpu, MemoryStick, Plug, ArrowRight, Plus, BellRing, CircleX,
} from 'lucide-react';
import { useAlerts, useAlertTriage } from './alerts/hooks';
import { isOpen } from './alerts/triage';
import {
  useClientCounts, useClientFlows, useRecentHunts, useRecentClients, useServerHealth, usePermission,
} from '../../lib/queries';
import { clientStatus, fmtBytes, fmtNum, pct, timeAgo, toDate, toNum } from '../../lib/format';
import {
  Badge, Button, Card, CardHeader, EmptyState, Segmented, Skeleton, Stat, StatusDot, Tooltip,
} from '../../ui/primitives';
import { effectiveState, HuntProgress, HuntStateBadge, huntCounts, huntTitle } from '../hunts/HuntBits';
import { useSelectedClient } from '../../shell/client-context';
import { AlertsPanel } from './alerts/AlertsPanel';
import { RapidHuntPanel } from './rapid/RapidHunt';

const RANGES = [
  { value: '3600', label: '1h' },
  { value: '21600', label: '6h' },
  { value: '86400', label: '24h' },
  { value: '604800', label: '7d' },
] as const;

type RangeValue = typeof RANGES[number]['value'];

export default function Dashboard() {
  const history = useHistory();
  const canHunt = usePermission('start_hunt');
  const counts = useClientCounts();
  const { data: hunts = [], isLoading: huntsLoading } = useRecentHunts();

  const running = useMemo(() => hunts.filter(h => effectiveState(h) === 'running'), [hunts]);
  const recentHunts = useMemo(() => {
    const r = [...running];
    for (const h of hunts) {
      if (r.length >= 6) break;
      if (!r.includes(h)) r.push(h);
    }
    return r.slice(0, 6);
  }, [hunts, running]);

  const total = counts.data?.total ?? 0;
  const online = counts.data?.online ?? 0;
  const runningClients = running.reduce((s, h) => s + huntCounts(h).running, 0);
  const { alerts, isLoading: alertsLoading } = useAlerts();
  const { record: triage } = useAlertTriage();
  // Open = not acknowledged/closed by anyone, and not suppressed.
  const newAlerts = useMemo(() => alerts.filter(a => isOpen(triage, a)), [alerts, triage]);
  const severe = newAlerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
  // Clients that failed in hunts created in the last 7 days.
  const recentFailures = useMemo(() => {
    const since = Date.now() - 7 * 24 * 3600 * 1000;
    return hunts.filter(h => (toDate(h.create_time)?.getTime() ?? 0) >= since)
      .reduce((s, h) => s + huntCounts(h).errors, 0);
  }, [hunts]);

  return (
    <div className="tw:flex-1 tw:overflow-y-auto">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-5">
        <div className="tw:flex tw:items-center tw:gap-3">
          <h1 className="tw:flex-1 tw:text-lg tw:font-semibold tw:tracking-tight">Dashboard</h1>
          {canHunt && (
            <Button variant="primary" icon={<Plus className="tw:size-3.5" />} onClick={() => history.push('/hunts?new=1')}>
              New hunt
            </Button>
          )}
        </div>

        {/* What an analyst opens the page for comes first. */}
        <RapidHuntPanel canHunt={canHunt} />

        <div className="tw:grid tw:grid-cols-2 tw:lg:grid-cols-4 tw:gap-4">
          <Stat icon={<BellRing />} label="Open alerts" tone={severe ? 'bad' : 'warn'}
            value={alertsLoading ? <Skeleton className="tw:h-7 tw:w-10" /> : fmtNum(newAlerts.length)}
            sub={severe ? `${fmtNum(severe)} critical or high` : 'None critical or high'}
            onClick={() => document.getElementById('alerts')?.scrollIntoView({ behavior: 'smooth' })} />
          <Stat icon={<Wifi />} label="Online now" tone="ok"
            value={counts.isLoading ? <Skeleton className="tw:h-7 tw:w-16" /> : `${fmtNum(online)} / ${fmtNum(total)}`}
            sub={total ? `${Math.round(pct(online, total))}% of enrolled clients, seen in the last 15 minutes` : 'Seen in the last 15 minutes'}
            onClick={() => history.push('/search/all?online=1')} />
          <Stat icon={<Crosshair />} label="Running hunts" tone="accent"
            value={huntsLoading ? <Skeleton className="tw:h-7 tw:w-10" /> : fmtNum(running.length)}
            sub={running.length ? `${fmtNum(runningClients)} clients still collecting` : `${fmtNum(hunts.length)} hunts in total`}
            onClick={() => history.push('/hunts')} />
          <Stat icon={<CircleX />} label="Failed hunt collections" tone={recentFailures ? 'bad' : 'info'}
            value={huntsLoading ? <Skeleton className="tw:h-7 tw:w-10" /> : fmtNum(recentFailures)}
            sub="Clients that errored in hunts from the last 7 days"
            onClick={() => history.push('/hunts')} />
        </div>

        <div id="alerts"><AlertsPanel /></div>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-3 tw:gap-4">
          <Card className="tw:xl:col-span-2">
            <CardHeader icon={<Crosshair className="tw:size-4" />} title="Hunts"
              subtitle={running.length ? `${running.length} running` : 'Nothing running right now'}
              actions={<Link to="/hunts" className="tw:text-xs tw:text-accent tw:hover:underline tw:flex tw:items-center tw:gap-1">All hunts <ArrowRight className="tw:size-3" /></Link>} />
            {huntsLoading ? (
              <div className="tw:p-4 tw:space-y-4">{[0, 1, 2].map(i => <Skeleton key={i} className="tw:h-8" />)}</div>
            ) : recentHunts.length === 0 ? (
              <EmptyState icon={<Crosshair />} title="No hunts yet"
                action={canHunt ? <Button size="sm" variant="primary" onClick={() => history.push('/hunts?new=1')}>Start a hunt</Button> : undefined}>
                Hunts collect artifacts from many endpoints at once.
              </EmptyState>
            ) : (
              <div className="tw:divide-y tw:divide-line">
                {recentHunts.map(h => {
                  const c = huntCounts(h);
                  return (
                    <Link key={h.hunt_id} to={`/hunts/${h.hunt_id}`} className="tw:flex tw:flex-wrap tw:sm:flex-nowrap tw:items-center tw:gap-x-4 tw:gap-y-2 tw:px-4 tw:py-3 tw:hover:bg-hover">
                      <div className="tw:min-w-0 tw:flex-1 tw:max-sm:basis-full">
                        <div className="tw:flex tw:items-center tw:gap-2">
                          <span className="tw:font-medium tw:text-[13px] tw:truncate">{huntTitle(h)}</span>
                          <HuntStateBadge hunt={h} />
                        </div>
                        <div className="tw:text-2xs tw:text-faint tw:mt-0.5 tw:font-mono tw:truncate">
                          {h.hunt_id} · {(h.artifacts ?? []).join(', ')}
                        </div>
                      </div>
                      <div className="tw:w-48 tw:max-sm:flex-1 tw:shrink-0 tw:space-y-1">
                        <HuntProgress hunt={h} />
                        <div className="tw:flex tw:justify-between tw:text-2xs tw:text-muted rx-num">
                          <span>{fmtNum(c.finished)}/{fmtNum(c.scheduled)} clients</span>
                          {c.errors > 0 ? <span className="tw:text-bad">{c.errors} failed</span> : <span>{fmtNum(c.rows)} rows</span>}
                        </div>
                      </div>
                      <span className="tw:text-2xs tw:text-faint tw:w-20 tw:text-right tw:shrink-0">{timeAgo(h.create_time)}</span>
                    </Link>
                  );
                })}
              </div>
            )}
          </Card>

          <RecentClients />
        </div>

        <ServerHealth />

        <ServerCollections />
      </div>
    </div>
  );
}

function RecentClients() {
  const { data = [], isLoading } = useRecentClients(8);
  const { setClient } = useSelectedClient();
  return (
    <Card>
      <CardHeader icon={<Wifi className="tw:size-4" />} title="Recently seen"
        actions={<Link to="/search/all" className="tw:text-xs tw:text-accent tw:hover:underline tw:flex tw:items-center tw:gap-1">All clients <ArrowRight className="tw:size-3" /></Link>} />
      {isLoading ? (
        <div className="tw:p-4 tw:space-y-3">{[0, 1, 2, 3].map(i => <Skeleton key={i} />)}</div>
      ) : data.length === 0 ? (
        <EmptyState icon={<Monitor />} title="No clients online">
          Deploy the client to endpoints and they will show up here.
        </EmptyState>
      ) : (
        <div className="tw:divide-y tw:divide-line">
          {data.map(c => (
            <Link key={c.client_id} to={`/host/${c.client_id}`} onClick={() => setClient(c)}
              className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2.5 tw:hover:bg-hover">
              <StatusDot status={clientStatus(c.last_seen_at)} />
              <div className="tw:min-w-0 tw:flex-1">
                <div className="tw:text-[13px] tw:font-medium tw:truncate">{c.os_info?.hostname || c.client_id}</div>
                <div className="tw:text-2xs tw:text-faint tw:truncate">
                  {[c.os_info?.system, c.os_info?.release].filter(Boolean).join(' · ')}
                </div>
              </div>
              <span className="tw:text-2xs tw:text-faint">{timeAgo(c.last_seen_at)}</span>
            </Link>
          ))}
        </div>
      )}
    </Card>
  );
}

function ServerHealth() {
  const [range, setRange] = useState<RangeValue>('3600');
  const { data, isLoading } = useServerHealth(Number(range));

  const points = useMemo(() => {
    const rows = data?.rows ?? [];
    // Down-sample to at most ~300 points so charts stay snappy.
    const step = Math.max(1, Math.floor(rows.length / 300));
    const out: { t: number; cpu: number; mem: number; conns: number }[] = [];
    for (let i = 0; i < rows.length; i += step) {
      const r = rows[i];
      out.push({
        t: toNum(r._ts as number),
        cpu: toNum(r.CPUPercent as number),
        mem: toNum(r.MemoryUse as number),
        conns: toNum(r.client_comms_current_connections as number),
      });
    }
    return out;
  }, [data]);

  const last = points[points.length - 1];

  return (
    <Card>
      <CardHeader icon={<Server className="tw:size-4" />} title="Server health"
        subtitle="Sampled by the Server.Monitor.Health event artifact"
        actions={<Segmented value={range} onChange={setRange} options={RANGES.map(r => ({ value: r.value, label: r.label }))} />} />
      {isLoading ? (
        <div className="tw:p-4 tw:grid tw:grid-cols-3 tw:gap-4">{[0, 1, 2].map(i => <Skeleton key={i} className="tw:h-40" />)}</div>
      ) : points.length === 0 ? (
        <EmptyState icon={<Server />} title="No health samples in this range">
          Make sure the Server.Monitor.Health server event artifact is enabled.
        </EmptyState>
      ) : (
        <div className="tw:grid tw:grid-cols-1 tw:lg:grid-cols-3 tw:divide-y tw:lg:divide-y-0 tw:lg:divide-x tw:divide-line">
          <MetricChart title="CPU" icon={<Cpu />} value={last ? `${Math.round(last.cpu)}%` : ''}
            data={points} dataKey="cpu" color="var(--rx-accent)" format={v => `${Math.round(v)}%`} range={Number(range)} />
          <MetricChart title="Memory" icon={<MemoryStick />} value={last ? fmtBytes(last.mem) : ''}
            data={points} dataKey="mem" color="var(--rx-info)" format={v => fmtBytes(v)} range={Number(range)} />
          <MetricChart title="Connected clients" icon={<Plug />} value={last ? fmtNum(last.conns) : ''}
            data={points} dataKey="conns" color="var(--rx-ok)" format={v => fmtNum(v)} range={Number(range)} />
        </div>
      )}
    </Card>
  );
}

function MetricChart({ title, icon, value, data, dataKey, color, format, range }: {
  title: string; icon: React.ReactNode; value: string; data: Record<string, number>[]; dataKey: string;
  color: string; format: (v: number) => string; range: number;
}) {
  const id = `grad-${dataKey}`;
  const tickFmt = (t: number) => {
    const d = new Date(t);
    return range > 86400
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
  };
  return (
    <div className="tw:p-4">
      <div className="tw:flex tw:items-center tw:gap-2 tw:mb-2">
        <span className="tw:text-faint tw:flex tw:[&>svg]:size-3.5">{icon}</span>
        <span className="tw:text-xs tw:text-muted">{title}</span>
        <span className="tw:ml-auto tw:text-[15px] tw:font-semibold rx-num">{value}</span>
      </div>
      <div className="tw:h-36">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--rx-line)" vertical={false} />
            <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickFmt}
              tick={{ fontSize: 10, fill: 'var(--rx-faint)' }} axisLine={false} tickLine={false} minTickGap={40} />
            <YAxis tickFormatter={v => format(v)} width={56}
              tick={{ fontSize: 10, fill: 'var(--rx-faint)' }} axisLine={false} tickLine={false} />
            <RTooltip
              contentStyle={{ background: 'var(--rx-raised)', border: '1px solid var(--rx-line)', borderRadius: 8, fontSize: 12 }}
              labelFormatter={t => new Date(Number(t)).toLocaleString()}
              formatter={(v: number) => [format(v), title]} />
            <Area type="monotone" dataKey={dataKey} stroke={color} strokeWidth={1.5} fill={`url(#${id})`} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function ServerCollections() {
  const { data, isLoading } = useClientFlows('server', 8);
  const rows = data?.rows ?? [];
  return (
    <Card>
      <CardHeader icon={<Server className="tw:size-4" />} title="Recent server collections"
        actions={<Link to="/collected/server" className="tw:text-xs tw:text-accent tw:hover:underline tw:flex tw:items-center tw:gap-1">All <ArrowRight className="tw:size-3" /></Link>} />
      {isLoading ? (
        <div className="tw:p-4 tw:space-y-3">{[0, 1, 2].map(i => <Skeleton key={i} />)}</div>
      ) : rows.length === 0 ? (
        <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">No server collections yet.</div>
      ) : (
        <div className="tw:divide-y tw:divide-line">
          {rows.map(r => {
            const state = String(r.State ?? '');
            const arts = (r.Artifacts as string[] | undefined) ?? [];
            return (
              <Link key={String(r.FlowId)} to={`/collected/server/${r.FlowId}`}
                className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2.5 tw:hover:bg-hover">
                <Badge tone={state === 'FINISHED' ? 'ok' : state === 'ERROR' ? 'bad' : 'accent'} dot>{state}</Badge>
                <span className="tw:font-mono tw:text-[12px] tw:truncate tw:flex-1">{arts.join(', ')}</span>
                <span className="tw:text-2xs tw:text-faint">{String(r.Creator ?? '')}</span>
                <Tooltip content={String(r.FlowId)}>
                  <span className="tw:text-2xs tw:text-faint tw:w-24 tw:text-right">{timeAgo(r.Created as number)}</span>
                </Tooltip>
              </Link>
            );
          })}
        </div>
      )}
    </Card>
  );
}
