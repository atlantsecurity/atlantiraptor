// Hunt feeds: Atlant Security's premium hunt packs. The server fetches
// the signed feed with the licence key an administrator entered and
// loads each pack as read-only Atlant.Feed.* artifacts; analysts start
// a pack as a hunt from here in one click.
import { useMemo, useState } from 'react';
import { Link, useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import {
  BadgeCheck, ChevronDown, ChevronRight, Crosshair, ExternalLink, KeyRound, Package, RefreshCw, Rss, ShieldAlert, Trash2,
} from 'lucide-react';
import {
  FEED_HUNT_TAG, feedHuntRequest, useFeedAction, useFeedStatus,
  type FeedHuntOptions, type FeedPack, type FeedStatus,
} from '../../lib/feeds';
import { useArtifactDefinitions, useCreateHunt, useHunts, usePermission } from '../../lib/queries';
import { timeAgo, toDate } from '../../lib/format';
import type { Hunt } from '../../lib/types';
import Markdown from '../../ui/Markdown';
import {
  Badge, Button, Card, CardHeader, ConfirmDialog, Dialog, EmptyState, Field, Input, Mono, SearchInput, Segmented, Select,
  Skeleton, Textarea, cn,
} from '../../ui/primitives';

const when = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleString() : 'never');
const day = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleDateString() : '');

const SEVERITY_TONE = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral', '': 'neutral' } as const;
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, '': 0 };
const OS_LABEL: Record<string, string> = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };
const DURATIONS = [1, 4, 24, 48, 72, 168];

export default function FeedsPage() {
  const { data, isLoading, error } = useFeedStatus();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<Rss />} title="Hunt feeds are not available">{(error as Error)?.message}</EmptyState>;
  }
  return <Feeds status={data} />;
}

function Feeds({ status }: { status: FeedStatus }) {
  const act = useFeedAction();
  const sync = () => act.mutate({ action: 'sync' }, {
    onSuccess: s => (s.last_error ? toast.error(s.last_error)
      : s.state === 'active' ? toast.success(`Feed is current: ${s.packs.length} packs`)
      : toast.error(s.message || 'The feed is not available')),
    onError: e => toast.error((e as Error).message),
  });

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-5xl">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1 tw:min-w-[240px]">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2">
              <Rss className="tw:size-5 tw:text-accent" />Hunt feeds
              <Badge tone="accent">Premium</Badge>
            </h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Hunt packs written and kept current by Atlant Security's threat hunters: detections for the
              techniques and tooling seen in current incidents, with up-to-date indicator lists. New and updated
              packs arrive by themselves; start any of them as a hunt in one click.
            </p>
          </div>
          {status.can_manage && status.has_key && (
            <Button icon={<RefreshCw className="tw:size-3.5" />} loading={status.syncing || act.isPending}
              disabled={status.syncing || act.isPending} onClick={sync}>Sync now</Button>
          )}
        </div>

        <Subscription status={status} />
        {status.state === 'active' && <Packs status={status} />}
      </div>
    </div>
  );
}

// ------------------------------------------------------------ Subscription

function Subscription({ status }: { status: FeedStatus }) {
  const act = useFeedAction();
  const [key, setKey] = useState('');
  const [changing, setChanging] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const save = () => act.mutate({ action: 'set_key', key: key.trim() }, {
    onSuccess: s => {
      setKey(''); setChanging(false);
      if (s.state === 'active') toast.success(`Subscription active: ${s.packs.length} hunt packs available`);
      else toast.error(s.message || s.last_error || 'The licence key was saved but the feed is not available yet');
    },
    onError: e => toast.error((e as Error).message),
  });
  const remove = () => act.mutate({ action: 'remove_key' }, {
    onSuccess: () => { setConfirmRemove(false); toast.success('Licence key removed'); },
    onError: e => { setConfirmRemove(false); toast.error((e as Error).message); },
  });

  const lic = status.licence;
  const tone = status.state === 'active' ? 'ok' : status.state === 'pending' ? 'warn' : status.state === 'unlicensed' ? 'neutral' : 'bad';
  const label: Record<FeedStatus['state'], string> = {
    active: 'Active', pending: 'Waiting for the feed', unlicensed: 'No subscription',
    expired: 'Subscription ended', invalid: 'Licence key not accepted', not_configured: 'Not available in this build',
  };
  const showForm = status.can_manage && status.state !== 'not_configured' && (!status.has_key || changing);

  return (
    <Card>
      <CardHeader icon={<KeyRound className="tw:size-4" />} title="Subscription"
        actions={<Badge tone={tone} dot>{label[status.state]}</Badge>} />
      <div className="tw:px-4 tw:py-3 tw:space-y-3 tw:text-[13px]">
        {status.state === 'active' && lic && (
          <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-3 tw:gap-3">
            <div><div className="tw:text-2xs tw:text-muted">Licensed to</div><div className="tw:font-medium">{lic.customer || '—'}</div></div>
            <div><div className="tw:text-2xs tw:text-muted">Plan</div><div className="tw:font-medium">{lic.plan || '—'}</div></div>
            <div><div className="tw:text-2xs tw:text-muted">Paid until</div><div className="tw:font-medium">{day(lic.expires)}</div></div>
          </div>
        )}

        {status.state === 'unlicensed' && (
          <p className="tw:text-muted">
            This server has no hunt feed subscription. Atlant Security's premium feed adds hunt packs for current threats,
            updated as our incident response team sees new tooling.{' '}
            <a href={status.subscribe_url} target="_blank" rel="noreferrer" className="tw:text-accent tw:inline-flex tw:items-center tw:gap-1">
              Get a subscription <ExternalLink className="tw:size-3" />
            </a>
            {!status.can_manage && ' A server administrator enters the licence key here.'}
          </p>
        )}
        {status.state === 'not_configured' && (
          <p className="tw:text-muted">This build of Atlantiraptor has no feed signing key, so it cannot verify feed content. Install an official release from Atlant Security.</p>
        )}
        {status.state === 'pending' && (
          <p className="tw:text-muted">{status.message || 'The licence key is saved. The server is fetching the feed.'}</p>
        )}
        {(status.state === 'expired' || status.state === 'invalid') && (
          <div className="tw:flex tw:gap-2 tw:items-start">
            <ShieldAlert className="tw:size-4 tw:text-bad tw:shrink-0 tw:mt-0.5" />
            <div>
              <div>{status.message}</div>
              <div className="tw:text-xs tw:text-muted tw:mt-1">
                The feed packs were removed from this server. Hunts that already ran keep their results.
                {status.state === 'expired' && ' Once the subscription is renewed, the packs come back at the next sync.'}{' '}
                <a href={status.subscribe_url} target="_blank" rel="noreferrer" className="tw:text-accent">Contact Atlant Security</a>
              </div>
            </div>
          </div>
        )}
        {status.last_error && <div className="tw:text-xs tw:text-bad">{status.last_error}</div>}

        {status.has_key && (
          <div className="tw:text-2xs tw:text-muted tw:space-y-0.5">
            {status.can_manage && <div>Licence key <Mono>{status.masked_key}</Mono>{status.key_set_by ? `, entered by ${status.key_set_by} ${when(status.key_set_at)}` : ''}</div>}
            <div>
              Last sync {when(status.last_sync)}
              {status.next_sync ? ` · next sync ${when(status.next_sync)}` : ''}
              {status.usable_until ? ` · works offline until ${when(status.usable_until)}` : ''}
            </div>
          </div>
        )}

        {showForm && (
          <form className="tw:flex tw:flex-wrap tw:items-end tw:gap-2" onSubmit={e => { e.preventDefault(); if (key.trim()) save(); }}>
            <Field label="Licence key" className="tw:flex-1 tw:min-w-[240px]">
              <Input value={key} onChange={e => setKey(e.target.value)} placeholder="ATL-XXXX-XXXX-XXXX" autoComplete="off" spellCheck={false} className="tw:font-mono" />
            </Field>
            <Button type="submit" variant="primary" loading={act.isPending} disabled={!key.trim() || act.isPending}>
              {status.has_key ? 'Replace key' : 'Activate'}
            </Button>
            {changing && <Button type="button" variant="ghost" onClick={() => { setChanging(false); setKey(''); }}>Cancel</Button>}
          </form>
        )}
        {status.can_manage && status.has_key && !changing && (
          <div className="tw:flex tw:gap-2">
            <Button size="sm" variant="ghost" icon={<KeyRound className="tw:size-3.5" />} onClick={() => setChanging(true)}>Change key</Button>
            <Button size="sm" variant="ghost" icon={<Trash2 className="tw:size-3.5" />} onClick={() => setConfirmRemove(true)}>Remove key</Button>
          </div>
        )}
      </div>
      <ConfirmDialog open={confirmRemove} onOpenChange={setConfirmRemove} title="Remove the licence key?" danger
        confirmLabel="Remove key" loading={act.isPending} onConfirm={remove}>
        The feed packs are removed from this server straight away. Hunts that already ran keep their results.
      </ConfirmDialog>
    </Card>
  );
}

// ------------------------------------------------------------ Packs

type Filter = 'all' | 'fresh';

function Packs({ status }: { status: FeedStatus }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<Filter>(status.new_count + status.updated_count > 0 ? 'fresh' : 'all');
  const [launch, setLaunch] = useState<FeedPack | null>(null);
  const { data: hunts } = useHunts(false);

  // The latest hunt started from each pack (tagged with its id).
  const lastHunt = useMemo(() => {
    const m = new Map<string, Hunt>();
    for (const h of hunts ?? []) {
      if (!h.tags?.includes(FEED_HUNT_TAG)) continue;
      for (const t of h.tags) {
        const prev = m.get(t);
        if (!prev || (toDate(h.create_time ?? null)?.getTime() ?? 0) > (toDate(prev.create_time ?? null)?.getTime() ?? 0)) m.set(t, h);
      }
    }
    return m;
  }, [hunts]);

  const ql = q.trim().toLowerCase();
  const shown = status.packs
    .filter(p => filter === 'all' || p.fresh)
    .filter(p => !ql || [p.name, p.id, p.summary, p.category, ...(p.tags ?? []), ...p.artifacts].join(' ').toLowerCase().includes(ql))
    .sort((a, b) => (b.fresh ? 1 : 0) - (a.fresh ? 1 : 0) || SEVERITY_RANK[b.severity ?? ''] - SEVERITY_RANK[a.severity ?? ''] || (b.updated ?? 0) - (a.updated ?? 0));

  return (
    <div className="tw:space-y-3">
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
        <Segmented<Filter> value={filter} onChange={setFilter} options={[
          { value: 'fresh', label: 'New and updated', count: status.new_count + status.updated_count },
          { value: 'all', label: 'All packs', count: status.packs.length },
        ]} />
        <SearchInput value={q} onChange={setQ} placeholder="Search packs, techniques, artifacts" className="tw:flex-1 tw:min-w-[200px]" />
      </div>
      {shown.length === 0 ? (
        <Card>
          <EmptyState icon={<Package />} title={filter === 'fresh' && !ql ? 'Nothing new in the last two weeks' : 'No packs match'}>
            {filter === 'fresh' && !ql ? 'Every pack is listed under All packs.' : undefined}
          </EmptyState>
        </Card>
      ) : shown.map(p => <PackCard key={p.id} pack={p} last={lastHunt.get(p.id)} onLaunch={() => setLaunch(p)} />)}
      {launch && <LaunchDialog pack={launch} onClose={() => setLaunch(null)} />}
    </div>
  );
}

function PackCard({ pack, last, onLaunch }: { pack: FeedPack; last?: Hunt; onLaunch: () => void }) {
  const [open, setOpen] = useState(false);
  const canHunt = usePermission('start_hunt');
  const lastTime = toDate(last?.create_time ?? null);
  const staleHunt = !!lastTime && !!pack.version_seen && lastTime.getTime() / 1000 < pack.version_seen;

  return (
    <Card>
      <div className="tw:px-4 tw:py-3 tw:flex tw:flex-wrap tw:gap-3 tw:items-start">
        <button type="button" onClick={() => setOpen(o => !o)} aria-expanded={open}
          className="tw:flex-1 tw:min-w-[240px] tw:text-left tw:flex tw:gap-2">
          <span className="tw:text-faint tw:mt-0.5">{open ? <ChevronDown className="tw:size-4" /> : <ChevronRight className="tw:size-4" />}</span>
          <span className="tw:min-w-0 tw:flex-1">
            <span className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5">
              <span className="tw:font-semibold tw:text-[14px]">{pack.name}</span>
              {pack.fresh === 'new' && <Badge tone="accent">New</Badge>}
              {pack.fresh === 'updated' && <Badge tone="info">Updated</Badge>}
              {pack.severity && <Badge tone={SEVERITY_TONE[pack.severity]}>{pack.severity}</Badge>}
              {(pack.platforms ?? []).map(os => <Badge key={os}>{OS_LABEL[os] ?? os}</Badge>)}
            </span>
            {pack.summary && <span className="tw:block tw:text-xs tw:text-muted tw:mt-1">{pack.summary}</span>}
            <span className="tw:block tw:text-2xs tw:text-faint tw:mt-1">
              {pack.category ? `${pack.category} · ` : ''}v{pack.version} · updated {day(pack.updated)}
              {last && lastTime ? <> · <Link to={`/hunts/${last.hunt_id}`} onClick={e => e.stopPropagation()} className="tw:text-accent">hunted {timeAgo(lastTime)}</Link></> : ' · not hunted yet'}
              {staleHunt && <span className="tw:text-warn"> · updated since the last hunt</span>}
            </span>
          </span>
        </button>
        <div className="tw:flex tw:items-center tw:gap-2">
          <Button variant="primary" icon={<Crosshair className="tw:size-3.5" />} onClick={onLaunch}
            disabled={!pack.installed || !canHunt}
            title={!canHunt ? 'You need permission to start hunts' : pack.install_error ? pack.install_error : undefined}>
            Launch hunt
          </Button>
        </div>
      </div>
      {pack.install_error && (
        <div className="tw:px-4 tw:pb-3 tw:text-xs tw:text-bad">This pack could not be loaded on this server: {pack.install_error}</div>
      )}
      {open && (
        <div className="tw:border-t tw:border-line tw:px-4 tw:py-3 tw:space-y-3 tw:text-[13px]">
          {pack.description && <Markdown text={pack.description} />}
          {pack.changes && (
            <div><div className="tw:text-2xs tw:text-muted tw:mb-0.5">What changed in v{pack.version}</div><Markdown text={pack.changes} /></div>
          )}
          <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
            <div>
              <div className="tw:text-2xs tw:text-muted tw:mb-1">Artifacts</div>
              <ul className="tw:space-y-0.5">
                {pack.artifacts.map(a => (
                  <li key={a}><Link to={`/artifacts/${encodeURIComponent(a)}`} className="tw:text-accent tw:font-mono tw:text-xs">{a}</Link></li>
                ))}
              </ul>
            </div>
            <div>
              <div className="tw:text-2xs tw:text-muted tw:mb-1">Hunt</div>
              <div className="tw:text-xs">
                {pack.hunt.os ? OS_LABEL[pack.hunt.os] : 'All'} clients · runs {hours(pack.hunt.expires_hours ?? 24)}
                {pack.hunt.cpu_limit ? ` · CPU limit ${pack.hunt.cpu_limit}%` : ''}
              </div>
            </div>
          </div>
          {!!pack.tags?.length && <div className="tw:flex tw:flex-wrap tw:gap-1">{pack.tags.map(t => <Badge key={t}>{t}</Badge>)}</div>}
          {!!pack.references?.length && (
            <div>
              <div className="tw:text-2xs tw:text-muted tw:mb-1">References</div>
              <ul className="tw:space-y-0.5 tw:text-xs">
                {pack.references.map(r => (
                  <li key={r}><a href={r} target="_blank" rel="noreferrer" className="tw:text-accent tw:break-all">{r}</a></li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function hours(h: number): string {
  if (h === 0) return 'until stopped';
  if (h % 24 === 0) return `${h / 24} day${h === 24 ? '' : 's'}`;
  return `${h} hour${h === 1 ? '' : 's'}`;
}

// ------------------------------------------------------------ Launch

function LaunchDialog({ pack, onClose }: { pack: FeedPack; onClose: () => void }) {
  const history = useHistory();
  const create = useCreateHunt();
  const artifacts = pack.hunt.artifacts?.length ? pack.hunt.artifacts : pack.artifacts;
  const { data: defs } = useArtifactDefinitions(artifacts);
  const [os, setOs] = useState<FeedHuntOptions['os']>(pack.hunt.os ?? '');
  const [duration, setDuration] = useState(pack.hunt.expires_hours ?? 24);
  // Only values the analyst changed are kept here; the rest come from
  // the pack's hunt parameters, then the artifact defaults.
  const [edits, setEdits] = useState<Record<string, Record<string, string>>>({});

  const value = (a: string, name: string, def?: string) =>
    edits[a]?.[name] ?? pack.hunt.parameters?.[a]?.[name] ?? def ?? '';

  const start = async () => {
    const parameters: Record<string, Record<string, string>> = {};
    for (const a of artifacts) {
      const d = defs?.get(a);
      const out: Record<string, string> = {};
      const names = new Set([...Object.keys(pack.hunt.parameters?.[a] ?? {}), ...Object.keys(edits[a] ?? {})]);
      for (const n of names) {
        const pd = d?.parameters?.find(p => p.name === n);
        const v = value(a, n, pd?.default);
        if (!pd || (pd.default ?? '') !== v) out[n] = v;
      }
      parameters[a] = out;
    }
    try {
      const r = await create.mutateAsync(feedHuntRequest(pack, { os, hours: duration, parameters }));
      toast.success(`Hunt started: ${pack.name}`);
      onClose();
      if (r.flow_id) history.push(`/hunts/${r.flow_id}`);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Dialog open onOpenChange={v => { if (!v) onClose(); }} width={640}
      title={<span className="tw:flex tw:items-center tw:gap-2"><Crosshair className="tw:size-4 tw:text-accent" />Hunt: {pack.name}</span>}
      description={`Version ${pack.version} from the Atlant Security feed`}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" icon={<Crosshair className="tw:size-3.5" />} loading={create.isPending} onClick={start} autoFocus>Start hunt</Button>
      </>}>
      <div className="tw:px-5 tw:pb-4 tw:space-y-4 tw:text-[13px]">
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3">
          <Field label="Clients">
            <Select value={os} onChange={e => setOs(e.target.value as FeedHuntOptions['os'])} className="tw:w-full">
              <option value="">All clients</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="darwin">macOS</option>
            </Select>
          </Field>
          <Field label="Runs for" hint="Clients that come online later still run it until then.">
            <Select value={duration} onChange={e => setDuration(Number(e.target.value))} className="tw:w-full">
              {[...new Set([...DURATIONS, duration])].filter(h => h > 0).sort((a, b) => a - b).map(h => <option key={h} value={h}>{hours(h)}</option>)}
              <option value={0}>Until stopped</option>
            </Select>
          </Field>
        </div>
        {artifacts.map(a => {
          const params = defs?.get(a)?.parameters ?? [];
          return (
            <div key={a} className="tw:space-y-2">
              <div className="tw:flex tw:items-center tw:gap-2">
                <BadgeCheck className="tw:size-3.5 tw:text-accent" />
                <Mono className="tw:text-xs">{a}</Mono>
              </div>
              {params.length === 0 && <div className="tw:text-xs tw:text-muted">No parameters.</div>}
              {params.map(p => {
                const v = value(a, p.name, p.default);
                const set = (nv: string) => setEdits(e => ({ ...e, [a]: { ...(e[a] ?? {}), [p.name]: nv } }));
                const multi = p.type === 'csv' || p.type === 'json' || v.includes('\n') || v.length > 80;
                return (
                  <Field key={p.name} label={p.name} hint={p.description}>
                    {multi
                      ? <Textarea rows={Math.min(8, Math.max(3, v.split('\n').length))} value={v} onChange={e => set(e.target.value)} className={cn('tw:font-mono tw:text-xs')} />
                      : <Input value={v} onChange={e => set(e.target.value)} className="tw:font-mono tw:text-xs" />}
                  </Field>
                );
              })}
            </div>
          );
        })}
        <p className="tw:text-2xs tw:text-muted">
          The hunt is tagged <Mono>{FEED_HUNT_TAG}</Mono> and <Mono>{pack.id}</Mono> so this page can show when each pack last ran.
        </p>
      </div>
    </Dialog>
  );
}
