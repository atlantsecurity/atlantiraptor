// Live response actions waiting for a second person, and the approval
// policy switch for admins. The approver sees the real request (target,
// mode and every parameter) as read-only data, apart from anything the
// requester typed.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, ShieldQuestion, X } from 'lucide-react';
import * as api from '../../lib/api';
import { useHunt } from '../../lib/queries';
import type { Hunt } from '../../lib/types';
import { timeAgo } from '../../lib/format';
import { Badge, Button, Card, CardHeader, Mono, Switch } from '../../ui/primitives';
import { useMe } from '../cases/hooks';
import { ONE_OFF_LABEL_PREFIX, requestOf, useApprovalActions, useApprovalPolicy, usePendingApprovals } from './approval';

export function ApprovalsPanel() {
  const policy = useApprovalPolicy();
  const pending = usePendingApprovals();

  return (
    <div className="tw:space-y-4">
      <Card>
        <CardHeader icon={<ShieldQuestion className="tw:size-4" />} title="Approval policy"
          subtitle="When on, live response actions start paused until a different user approves them." />
        <div className="tw:px-4 tw:pb-4 tw:space-y-2">
          {policy.readable ? (
            <Switch checked={policy.required} label="Require a second person to approve live response actions"
              onChange={async v => {
                try { await policy.set(v); toast.success(v ? 'Approval required' : 'Approval no longer required'); }
                catch (e) { toast.error((e as Error).message); }
              }} />
          ) : (
            <div className="tw:text-xs tw:text-muted">Only server admins can change this. Until it can be read, live actions are sent for approval.</div>
          )}
          <p className="tw:text-2xs tw:text-faint">
            This is a workflow check in the console. Users with the start-hunt permission can still start hunts directly through the API. The server audit log records who requested, approved and started each action.
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader title="Waiting for approval" subtitle={pending.length ? `${pending.length} pending` : 'Nothing waiting'} />
        <div className="tw:divide-y tw:divide-line">
          {pending.length === 0 && <div className="tw:px-4 tw:py-6 tw:text-center tw:text-xs tw:text-faint">No live actions are waiting.</div>}
          {pending.map(h => <PendingRow key={h.hunt_id} id={h.hunt_id} />)}
        </div>
      </Card>
    </div>
  );
}

function useOneOffHost(h: Hunt | undefined) {
  const label = (h?.condition?.labels?.label ?? []).find(l => l.startsWith(ONE_OFF_LABEL_PREFIX));
  return useQuery({
    queryKey: ['one-off-host', label],
    enabled: !!label,
    queryFn: () => api.get<{ items?: { client_id: string; os_info?: { hostname?: string } }[] }>('v1/SearchClients',
      { query: `label:${label}`, limit: 5 }),
    select: d => (d.items ?? []).map(c => `${c.os_info?.hostname || c.client_id} (${c.client_id})`),
  });
}

function targetOf(h: Hunt, oneOff: string[] | undefined): string {
  const c = h.condition ?? {};
  const labels = c.labels?.label ?? [];
  const except = c.excluded_labels?.label?.length ? `, except labels ${c.excluded_labels.label.join(', ')}` : '';
  if (labels.some(l => l.startsWith(ONE_OFF_LABEL_PREFIX))) return `Single host: ${oneOff?.join(', ') || 'resolving…'}`;
  if (labels.length) return `Clients labelled ${labels.join(', ')}${except}`;
  if (c.os?.os) return `All ${c.os.os} clients${except}`;
  return `All clients${except}`;
}

function PendingRow({ id }: { id: string }) {
  const { data: hunt } = useHunt(id);
  const { data: oneOff } = useOneOffHost(hunt);
  const me = useMe();
  const actions = useApprovalActions();
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null);
  if (!hunt) return <div className="tw:px-4 tw:py-3 tw:text-xs tw:text-faint">Loading {id}…</div>;

  const req = requestOf(hunt);
  const own = hunt.creator === me;
  const specs = hunt.start_request?.specs ?? [];
  const env = specs.flatMap(s => s.parameters?.env ?? []);
  const arm = env.find(e => e.key === 'ReallyDoIt');
  const live = arm ? arm.value === 'Y' : true;

  const act = async (kind: 'approve' | 'reject') => {
    setBusy(kind);
    try {
      await (kind === 'approve' ? actions.approve(id, me === 'unknown' ? '' : me) : actions.reject(id, me === 'unknown' ? '' : me));
      toast.success(kind === 'approve' ? 'Approved and started' : own ? 'Withdrawn' : 'Rejected');
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="tw:px-4 tw:py-3 tw:space-y-2">
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
        <Link to={`/hunts/${id}`} className="tw:font-mono tw:text-[12px] tw:text-accent tw:hover:underline">{id}</Link>
        {live ? <Badge tone="bad">Live</Badge> : <Badge tone="info">Dry run</Badge>}
        <span className="tw:text-2xs tw:text-faint">requested by <b className="tw:text-muted">{hunt.creator}</b> · {timeAgo(hunt.create_time)}</span>
        {own && <Badge tone="neutral">Your request</Badge>}
      </div>

      <dl className="tw:grid tw:grid-cols-[90px_1fr] tw:gap-x-3 tw:gap-y-1 tw:text-xs tw:rounded-md tw:border tw:border-line tw:bg-canvas/50 tw:p-2.5">
        <dt className="tw:text-muted">Target</dt><dd>{targetOf(hunt, oneOff)}</dd>
        <dt className="tw:text-muted">Artifacts</dt><dd className="tw:font-mono tw:text-[11px]">{(hunt.start_request?.artifacts ?? []).join(', ')}</dd>
        <dt className="tw:text-muted">Parameters</dt>
        <dd className="tw:space-y-0.5">
          {env.length === 0 && <span className="tw:text-faint">Defaults</span>}
          {Array.from(new Map(env.map(e => [e.key, e.value])).entries()).map(([k, v]) => (
            <div key={k} className="tw:flex tw:gap-2"><span className="tw:text-muted tw:shrink-0">{k}</span><Mono className="tw:text-[11px] tw:whitespace-pre-wrap tw:break-all">{v}</Mono></div>
          ))}
        </dd>
      </dl>

      <div className="tw:text-xs">
        <span className="tw:text-muted">Requester's reason (their own words): </span>
        <span className="tw:whitespace-pre-wrap tw:break-words">{req?.reason || '—'}</span>
      </div>

      <div className="tw:flex tw:items-center tw:gap-1.5 tw:justify-end">
        <Button size="sm" variant="ghost" icon={<X className="tw:size-3.5" />} loading={busy === 'reject'} disabled={!!busy}
          onClick={() => act('reject')}>{own ? 'Withdraw' : 'Reject'}</Button>
        <Button size="sm" variant="danger" icon={<Check className="tw:size-3.5" />} loading={busy === 'approve'}
          disabled={!!busy || own || me === 'unknown'} onClick={() => act('approve')}>Approve and run</Button>
      </div>
    </div>
  );
}
