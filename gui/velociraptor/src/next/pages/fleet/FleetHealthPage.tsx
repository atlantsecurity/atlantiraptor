// Fleet health: who is offline, which agents are behind, which hunts are
// failing, and one-click upgrades for outdated agents.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowUpCircle, Clock, HeartPulse, Layers, Wifi } from 'lucide-react';
import { useClientSearch, useHunts, usePermission } from '../../lib/queries';
import type { ApiClient } from '../../lib/types';
import { fmtNum, timeAgo, toNum } from '../../lib/format';
import { Badge, Button, Card, CardHeader, EmptyState, Segmented, Skeleton, Stat } from '../../ui/primitives';
import { huntCounts, huntTitle } from '../hunts/HuntBits';
import { fleetStats, osKey, UPGRADE } from './model';
import { UpgradeDialog } from './UpgradeDialog';

const CLIENT_LIMIT = 10_000;

export default function FleetHealthPage() {
  const { data, isLoading } = useClientSearch('all', { limit: CLIENT_LIMIT });
  const clients = useMemo(() => (data?.items ?? []) as ApiClient[], [data]);
  const stats = useMemo(() => fleetStats(clients), [clients]);
  const canHunt = usePermission('start_hunt');
  const [upgrade, setUpgrade] = useState<keyof typeof UPGRADE | null>(null);
  const outdatedBy = (os: keyof typeof UPGRADE) => stats.outdated.filter(c => osKey(c) === os);

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><HeartPulse className="tw:size-5 tw:text-accent" />Fleet health</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">Agents that went quiet, agents running old versions, and collections that keep failing.</p>
        </div>

        <div className="tw:grid tw:grid-cols-2 tw:lg:grid-cols-4 tw:gap-4">
          <Stat icon={<Wifi />} label="Online now" tone="ok" value={isLoading ? <Skeleton className="tw:h-7 tw:w-12" /> : `${fmtNum(stats.online)} / ${fmtNum(stats.total)}`} sub="Seen in the last 15 minutes" />
          <Stat icon={<Clock />} label="Quiet 7–30 days" tone="warn" value={isLoading ? <Skeleton className="tw:h-7 tw:w-12" /> : fmtNum(stats.stale7.length)} sub="May be off or uninstalled" />
          <Stat icon={<AlertTriangle />} label="Quiet over 30 days" tone="bad" value={isLoading ? <Skeleton className="tw:h-7 tw:w-12" /> : fmtNum(stats.stale30.length)} sub="Likely gone; consider removing" />
          <Stat icon={<Layers />} label="Behind latest version" tone="info" value={isLoading ? <Skeleton className="tw:h-7 tw:w-12" /> : fmtNum(stats.outdated.length)} sub={stats.latest ? `Latest in fleet: ${stats.latest}` : 'No version data'} />
        </div>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          <Card>
            <CardHeader icon={<Layers className="tw:size-4" />} title="Agent versions"
              actions={<div className="tw:flex tw:gap-1.5">
                {(Object.keys(UPGRADE) as (keyof typeof UPGRADE)[]).map(os => outdatedBy(os).length > 0 && (
                  <Button key={os} size="sm" variant="secondary" icon={<ArrowUpCircle className="tw:size-3.5" />} disabled={!canHunt}
                    onClick={() => setUpgrade(os)}>Upgrade {outdatedBy(os).length} {UPGRADE[os].label}</Button>
                ))}
              </div>} />
            <div className="tw:divide-y tw:divide-line">
              {stats.versions.length === 0 && <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">No clients.</div>}
              {stats.versions.map(v => (
                <div key={v.version} className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2 tw:text-xs">
                  <span className="tw:font-mono tw:flex-1">{v.version}</span>
                  {v.version === stats.latest && <Badge tone="ok">Latest</Badge>}
                  {v.outdated && <Badge tone="warn">Outdated</Badge>}
                  <span className="rx-num tw:w-16 tw:text-right">{fmtNum(v.count)} hosts</span>
                </div>
              ))}
            </div>
          </Card>
          <FailingHunts />
        </div>

        <StaleClients stale7={stats.stale7} stale30={stats.stale30} />
      </div>
      {upgrade && <UpgradeDialog os={upgrade} clients={outdatedBy(upgrade)} onClose={() => setUpgrade(null)} />}
    </div>
  );
}

function StaleClients({ stale7, stale30 }: { stale7: ApiClient[]; stale30: ApiClient[] }) {
  const [which, setWhich] = useState<'7' | '30'>('30');
  const list = (which === '30' ? stale30 : stale7).slice(0, 200);
  return (
    <Card>
      <CardHeader icon={<Clock className="tw:size-4" />} title="Quiet agents"
        actions={<Segmented value={which} onChange={v => setWhich(v as '7' | '30')}
          options={[{ value: '30', label: `Over 30 days (${stale30.length})` }, { value: '7', label: `7–30 days (${stale7.length})` }]} />} />
      {list.length === 0 ? <EmptyState icon={<Wifi />} title="Nothing here">Every agent in this range has checked in.</EmptyState> : (
        <div className="tw:divide-y tw:divide-line">
          {list.map(c => (
            <Link key={c.client_id} to={`/host/${c.client_id}`} className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-2 tw:text-xs tw:hover:bg-hover">
              <span className="tw:font-medium tw:flex-1 tw:truncate">{c.os_info?.hostname || c.client_id}</span>
              <span className="tw:text-faint tw:font-mono">{c.agent_information?.version}</span>
              <span className="tw:text-muted tw:capitalize tw:w-16">{c.os_info?.system}</span>
              <span className="tw:text-faint tw:w-28 tw:text-right">seen {timeAgo(c.last_seen_at)}</span>
            </Link>
          ))}
        </div>
      )}
    </Card>
  );
}

function FailingHunts() {
  const { data: hunts = [] } = useHunts(false);
  const rows = useMemo(() => hunts.map(h => ({ h, c: huntCounts(h) }))
    .filter(x => x.c.errors > 0)
    .sort((a, b) => toNum(b.h.create_time) - toNum(a.h.create_time)).slice(0, 15), [hunts]);
  return (
    <Card>
      <CardHeader icon={<Activity className="tw:size-4" />} title="Failing collections" subtitle="Hunts where some clients returned errors" />
      <div className="tw:divide-y tw:divide-line">
        {rows.length === 0 && <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">No hunt has failed clients.</div>}
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
