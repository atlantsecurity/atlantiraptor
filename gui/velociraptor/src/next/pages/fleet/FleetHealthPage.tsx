// Fleet health: who is offline, which agents are behind, which hunts are
// failing, and one-click upgrades for outdated agents. The counts come
// from the server (v1/atl/fleet), so the page stays light on big fleets.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, ArrowUpCircle, Clock, HeartPulse, Layers, Wifi } from 'lucide-react';
import * as api from '../../lib/api';
import { POLL, useRecentHunts, usePermission } from '../../lib/queries';
import { fmtNum, timeAgo, toNum } from '../../lib/format';
import { Badge, Button, Card, CardHeader, EmptyState, Segmented, Skeleton, Stat } from '../../ui/primitives';
import { huntCounts, huntTitle } from '../hunts/HuntBits';
import { fleetVersions, UPGRADE, type FleetHost, type FleetSummary, type UpgradeOs } from './model';
import { UpgradeDialog } from './UpgradeDialog';

function useFleetSummary() {
  return useQuery({
    queryKey: ['fleet-summary'],
    queryFn: ({ signal }) => api.get<FleetSummary>('v1/atl/fleet', {}, signal),
    refetchInterval: POLL.slow * 2,
  });
}

export default function FleetHealthPage() {
  const { data, isLoading } = useFleetSummary();
  const versions = useMemo(() => fleetVersions(data?.versions ?? []), [data]);
  const canHunt = usePermission('start_hunt');
  const [upgrade, setUpgrade] = useState<UpgradeOs | null>(null);
  const latestText = Object.entries(versions.latestByOs).map(([os, v]) => `${os} ${v}`).join(', ');
  const loading = (v: React.ReactNode) => (isLoading ? <Skeleton className="tw:h-7 tw:w-12" /> : v);

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><HeartPulse className="tw:size-5 tw:text-accent" />Fleet health</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">Agents that went quiet, agents running old versions, and collections that keep failing.</p>
        </div>

        <div className="tw:grid tw:grid-cols-2 tw:lg:grid-cols-4 tw:gap-4">
          <Stat icon={<Wifi />} label="Online now" tone="ok" value={loading(`${fmtNum(data?.online ?? 0)} / ${fmtNum(data?.total ?? 0)}`)} sub="Seen in the last 15 minutes" />
          <Stat icon={<Clock />} label="Quiet 7–30 days" tone="warn" value={loading(fmtNum(data?.quiet_7_count ?? 0))} sub="May be off or uninstalled" />
          <Stat icon={<AlertTriangle />} label="Quiet over 30 days" tone="bad" value={loading(fmtNum(data?.quiet_30_count ?? 0))} sub="Likely gone; consider removing" />
          <Stat icon={<Layers />} label="Behind latest version" tone="info" value={loading(fmtNum(versions.outdatedTotal))} sub={latestText ? `Latest in fleet: ${latestText}` : 'No version data'} />
        </div>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          <Card>
            <CardHeader icon={<Layers className="tw:size-4" />} title="Agent versions"
              actions={<div className="tw:flex tw:gap-1.5">
                {(Object.keys(UPGRADE) as UpgradeOs[]).map(os => (versions.outdatedByOs[os]?.count ?? 0) > 0 && (
                  <Button key={os} size="sm" variant="secondary" icon={<ArrowUpCircle className="tw:size-3.5" />} disabled={!canHunt}
                    onClick={() => setUpgrade(os)}>Upgrade {fmtNum(versions.outdatedByOs[os].count)} {UPGRADE[os].label}</Button>
                ))}
              </div>} />
            <div className="tw:divide-y tw:divide-line">
              {!isLoading && versions.rows.length === 0 && <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">No clients.</div>}
              {versions.rows.map(v => (
                <div key={`${v.os}/${v.version}`} className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2 tw:text-xs">
                  <span className="tw:font-mono tw:flex-1">{v.version}</span>
                  <span className="tw:text-muted tw:capitalize tw:w-16">{v.os || 'unknown'}</span>
                  {v.latest && <Badge tone="ok">Latest</Badge>}
                  {v.outdated && <Badge tone="warn">Outdated</Badge>}
                  <span className="rx-num tw:w-20 tw:text-right">{fmtNum(v.count)} hosts</span>
                </div>
              ))}
            </div>
          </Card>
          <FailingHunts />
        </div>

        <QuietClients summary={data} />
      </div>
      {upgrade && <UpgradeDialog os={upgrade} versions={versions.outdatedByOs[upgrade]?.versions ?? []}
        expected={versions.outdatedByOs[upgrade]?.count ?? 0} onClose={() => setUpgrade(null)} />}
    </div>
  );
}

function QuietClients({ summary }: { summary?: FleetSummary }) {
  const [which, setWhich] = useState<'7' | '30'>('30');
  const list: FleetHost[] = (which === '30' ? summary?.quiet_30 : summary?.quiet_7) ?? [];
  const total = (which === '30' ? summary?.quiet_30_count : summary?.quiet_7_count) ?? 0;
  return (
    <Card>
      <CardHeader icon={<Clock className="tw:size-4" />} title="Quiet agents"
        subtitle={total > list.length ? `Showing the ${list.length} quiet the longest of ${fmtNum(total)}` : undefined}
        actions={<Segmented value={which} onChange={v => setWhich(v as '7' | '30')}
          options={[{ value: '30', label: `Over 30 days (${fmtNum(summary?.quiet_30_count ?? 0)})` },
            { value: '7', label: `7–30 days (${fmtNum(summary?.quiet_7_count ?? 0)})` }]} />} />
      {list.length === 0 ? <EmptyState icon={<Wifi />} title="Nothing here">Every agent in this range has checked in.</EmptyState> : (
        <div className="tw:divide-y tw:divide-line">
          {list.map(c => (
            <Link key={c.client_id} to={`/host/${c.client_id}`} className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2 tw:text-xs tw:hover:bg-hover">
              <span className="tw:font-medium tw:flex-1 tw:truncate">{c.hostname || c.client_id}</span>
              <span className="tw:text-faint tw:font-mono">{c.version}</span>
              <span className="tw:text-muted tw:capitalize tw:w-16">{c.os}</span>
              <span className="tw:text-faint tw:w-28 tw:text-right">seen {timeAgo(c.last_seen_at)}</span>
            </Link>
          ))}
        </div>
      )}
    </Card>
  );
}

function FailingHunts() {
  const { data: hunts = [] } = useRecentHunts();
  const rows = useMemo(() => hunts.map(h => ({ h, c: huntCounts(h) }))
    .filter(x => x.c.errors > 0)
    .sort((a, b) => toNum(b.h.create_time) - toNum(a.h.create_time)).slice(0, 15), [hunts]);
  return (
    <Card>
      <CardHeader icon={<Activity className="tw:size-4" />} title="Failing collections" subtitle="Recent hunts where some clients returned errors" />
      <div className="tw:divide-y tw:divide-line">
        {rows.length === 0 && <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">No recent hunt has failed clients.</div>}
        {rows.map(({ h, c }) => (
          <Link key={h.hunt_id} to={`/hunts/${h.hunt_id}`} className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2 tw:text-xs tw:hover:bg-hover">
            <span className="tw:flex-1 tw:truncate">{huntTitle(h)}</span>
            <Badge tone="bad">{c.errors} failed</Badge>
            <span className="tw:text-faint tw:w-24 tw:text-right">of {c.scheduled} · {timeAgo(h.create_time)}</span>
          </Link>
        ))}
      </div>
    </Card>
  );
}
