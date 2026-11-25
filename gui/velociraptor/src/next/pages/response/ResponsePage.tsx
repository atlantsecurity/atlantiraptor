// Fleet response: pick an action, pick targets, confirm, and the action
// runs as a hunt across every matching client. Progress and per-client
// results live in the hunt; recent actions are listed below.
import { useEffect, useMemo, useState } from 'react';
import { useHistory, useLocation, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Play, Siren } from 'lucide-react';
import {
  runArtifacts, useClient, useCreateHunt, useEstimateHunt, usePermission, type CreateHuntRequest,
} from '../../lib/queries';
import type { HuntCondition } from '../../lib/types';
import * as api from '../../lib/api';
import { Badge, Button, Card, CardHeader, Input, Segmented, Select, Switch, Textarea, cn } from '../../ui/primitives';
import { useMe } from '../cases/hooks';
import { newId } from '../cases/model';
import { ApprovalsPanel } from './ApprovalsPanel';
import { AuditLog } from './AuditLog';
import {
  encodeUserData, HUNT_PAUSED, ONE_OFF_LABEL_PREFIX, oneLine, PENDING_TAG, useApprovalPolicy, usePendingApprovals,
} from './approval';
import { TagInput } from '../hunts/TagInput';
import { ACTIONS, GROUPS, RESPONSE_TAG, type ResponseAction } from './actions';
import { ConfirmResponseDialog } from './ConfirmResponseDialog';
import { ClientPicker, type PickedClient } from './ClientPicker';
import { ResponseHistory } from './ResponseHistory';

type TargetMode = 'clients' | 'labels' | 'os' | 'all';
const OS_LABEL: Record<string, string> = { WINDOWS: 'Windows', LINUX: 'Linux', OSX: 'macOS' };
const CLIENT_ID_RE = /^C\.[0-9a-f]+(-[A-Za-z0-9]+)?$/;

// Field values may be prefilled from the URL (for example by an alert's
// "Delete file" action). They are only ever placed into the form, so the
// person still reviews and confirms them.
function initialValues(a: ResponseAction, prefill: URLSearchParams): Record<string, string> {
  return Object.fromEntries(a.fields.map(f => [f.key, prefill.get(f.key) ?? f.initial ?? '']));
}

export default function ResponsePage() {
  const { action: actionId } = useParams<{ action?: string }>();
  const history = useHistory();
  const { search } = useLocation();
  const query = useMemo(() => new URLSearchParams(search), [search]);
  const rawClient = query.get('client') ?? '';
  const clientId = CLIENT_ID_RE.test(rawClient) ? rawClient : '';
  const action = ACTIONS.find(a => a.id === actionId) ?? ACTIONS[0];
  const canHunt = usePermission('start_hunt');
  const canCollect = usePermission('collect_client');
  // Hunts need START_HUNT; a single host needs COLLECT_CLIENT, plus
  // START_HUNT when the action has to wait for approval.
  const canRun = clientId ? canCollect : canHunt;
  const [tab, setTab] = useState<'actions' | 'approvals' | 'audit'>(query.get('tab') === 'audit' ? 'audit' : 'actions');
  const pending = usePendingApprovals();

  return (
    <div className="tw:flex-1 tw:overflow-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-5">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Siren className="tw:size-5 tw:text-bad" />Response</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Send a response action to many clients at once. Each action runs as a hunt, so hosts that are offline act when they next check in.
            </p>
          </div>
          <Segmented value={tab} onChange={v => setTab(v as typeof tab)}
            options={[{ value: 'actions', label: 'Actions' },
              { value: 'approvals', label: pending.length ? `Approvals (${pending.length})` : 'Approvals' },
              { value: 'audit', label: 'Audit log' }]} />
        </div>
        {tab === 'actions' && <>
          <div className="tw:grid tw:grid-cols-1 tw:lg:grid-cols-[280px_1fr] tw:gap-4 tw:items-start">
            <ActionList selected={action.id}
              onSelect={id => history.push(`/response/${id}${clientId ? `?client=${clientId}` : ''}`)} />
            <ActionForm key={`${action.id}-${clientId}`} action={action} canRun={canRun} clientId={clientId} prefill={query} />
          </div>
          <ResponseHistory />
        </>}
        {tab === 'approvals' && <ApprovalsPanel />}
        {tab === 'audit' && <AuditLog />}
      </div>
    </div>
  );
}

function ActionList({ selected, onSelect }: { selected: string; onSelect: (id: string) => void }) {
  return (
    <Card className="tw:p-2">
      {GROUPS.map(g => (
        <div key={g}>
          <div className="tw:px-2 tw:pt-3 tw:pb-1 tw:text-2xs tw:font-semibold tw:uppercase tw:tracking-wider tw:text-faint">{g}</div>
          {ACTIONS.filter(a => a.group === g).map(a => (
            <button key={a.id} type="button" onClick={() => onSelect(a.id)}
              className={cn('tw:flex tw:w-full tw:items-center tw:gap-2.5 tw:rounded-md tw:px-2 tw:h-8 tw:text-left tw:text-[13px]',
                a.id === selected ? 'tw:bg-active tw:text-fg tw:font-medium' : 'tw:text-muted tw:hover:bg-hover tw:hover:text-fg')}>
              <span className={cn('tw:flex tw:[&>svg]:size-4', a.id === selected && 'tw:text-accent')}>{a.icon}</span>
              <span className="tw:truncate">{a.title}</span>
            </button>
          ))}
        </div>
      ))}
    </Card>
  );
}

interface ActionFormProps {
  action: ResponseAction;
  canRun: boolean;
  clientId: string;
  prefill: URLSearchParams;
}

function ActionForm({ action, canRun, clientId, prefill }: ActionFormProps) {
  const history = useHistory();
  const create = useCreateHunt();
  const { data: client } = useClient(clientId || undefined);
  const [values, setValues] = useState(() => initialValues(action, prefill));
  const [mode, setMode] = useState<TargetMode>(clientId ? 'clients' : 'labels');
  const [picked, setPicked] = useState<PickedClient[]>(() => (clientId ? [{ id: clientId, hostname: clientId }] : []));
  // Show the hostname once the client page's client has loaded.
  useEffect(() => {
    if (client?.os_info?.hostname) {
      setPicked(ps => ps.map(p => (p.id === clientId && p.hostname === clientId ? { ...p, hostname: client.os_info!.hostname! } : p)));
    }
  }, [client, clientId]);
  const [labels, setLabels] = useState<string[]>([]);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [os, setOs] = useState('WINDOWS');
  const [dryRun, setDryRun] = useState(!!action.armParam);
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState('');
  const me = useMe();
  const canHunt = usePermission('start_hunt');
  const policy = useApprovalPolicy();
  const needsApproval = !dryRun && policy.required;
  const userData = encodeUserData({
    reason: reason.trim(), requested_by: me, approval: needsApproval ? 'required' : 'not-required',
  });

  const condition: HuntCondition = useMemo(() => {
    const c: HuntCondition = {};
    if (mode === 'labels' && labels.length) c.labels = { label: labels };
    if (mode === 'os') c.os = { os };
    if (excluded.length && mode !== 'clients') c.excluded_labels = { label: excluded };
    return c;
  }, [mode, labels, excluded, os]);
  const missingLabels = mode === 'labels' && labels.length === 0;
  const missingClients = mode === 'clients' && picked.length === 0;
  const estimate = useEstimateHunt(condition, 'all', !missingLabels && mode !== 'clients');
  const hostCount = mode === 'clients' ? picked.length : missingLabels ? undefined : estimate.data;
  // One host without approval runs as a direct collection; anything else
  // (several hosts, or waiting for approval) becomes a hunt.
  const direct = mode === 'clients' && picked.length === 1 && !needsApproval;

  const missing = action.fields.filter(f => f.required && !(values[f.key] ?? '').trim());
  const missingReason = !dryRun && !reason.trim();
  // A single host waiting for approval becomes a labelled hunt, which
  // needs the hunt permission too.
  const permitted = canRun && (direct || mode !== 'clients' || canHunt);
  const blocked = !permitted || !policy.loaded || missingLabels || missingClients || missing.length > 0 || missingReason;

  const params: Record<string, string> = useMemo(() => {
    const p: Record<string, string> = { ...action.fixed };
    for (const f of action.fields) {
      const v = (values[f.key] ?? '').trim();
      if (v) p[f.key] = f.kind === 'textarea' ? values[f.key] : v;
    }
    if (action.armParam) p[action.armParam] = dryRun ? 'N' : 'Y';
    return p;
  }, [action, values, dryRun]);

  const targetText = mode === 'clients'
    ? (picked.length === 1 ? `Only ${picked[0].hostname} (${picked[0].id})` : `These ${picked.length} clients: ${picked.slice(0, 5).map(p => p.hostname).join(', ')}${picked.length > 5 ? '…' : ''}`)
    : mode === 'all' ? 'All clients'
    : mode === 'os' ? `All ${OS_LABEL[os]} clients`
    : `Clients labelled ${labels.join(', ') || '…'}`;
  const fullTarget = excluded.length && mode !== 'clients' ? `${targetText}, except ${excluded.join(', ')}` : targetText;

  // One host without approval: a direct collection. Several hosts, or
  // any host waiting for approval: the hosts get one one-off label and a
  // hunt targets that label. The request records exactly which hosts,
  // so the approval queue can check the label covers just those.
  const startOnClients = async () => {
    if (direct) {
      const target = picked[0];
      const per = Object.fromEntries(action.artifacts.map(a => [a, params]));
      const r = await runArtifacts(target.id, action.artifacts, per, true, userData);
      toast.success(dryRun ? 'Dry run started' : `${action.title} started on ${target.hostname}`);
      setConfirming(false);
      if (r.flow_id) history.push(`/collected/${target.id}/${r.flow_id}`);
      return;
    }
    const ids = picked.map(p => p.id);
    const label = `${ONE_OFF_LABEL_PREFIX}${newId()}`;
    await api.post('v1/LabelClients', { client_ids: ids, labels: [label], operation: 'set' });
    try {
      return await startHunt({ labels: { label: [label] } }, label, ids);
    } catch (e) {
      await api.post('v1/LabelClients', { client_ids: ids, labels: [label], operation: 'remove' }).catch(() => undefined);
      throw e;
    }
  };
  const startHunt = async (cond: HuntCondition, oneOffLabel?: string, oneOffClients?: string[]) => {
    const huntUserData = oneOffLabel
      ? encodeUserData({
        reason: reason.trim(), requested_by: me, approval: needsApproval ? 'required' : 'not-required',
        one_off_label: oneOffLabel, one_off_clients: oneOffClients,
      })
      : userData;
    const env = Object.entries(params).map(([key, value]) => ({ key, value }));
    const why = reason.trim() ? ` – reason: ${oneLine(reason)}` : '';
    const req: CreateHuntRequest = {
      hunt_description: `Response: ${action.summary(values)}${dryRun ? ' (dry run)' : ''}${why}`,
      tags: [RESPONSE_TAG, action.id, ...(dryRun ? ['dry-run'] : []), ...(needsApproval ? [PENDING_TAG] : [])],
      start_request: {
        artifacts: action.artifacts,
        specs: action.artifacts.map(artifact => ({ artifact, parameters: { env } })),
        urgent: true,
        user_data: huntUserData,
      },
      condition: cond,
      // Paused (1) while waiting for approval, otherwise running (2).
      state: needsApproval ? HUNT_PAUSED : 2,
    };
    const r = await create.mutateAsync(req);
    toast.success(needsApproval ? 'Sent for approval. Another user must approve it in Response › Approvals.'
      : dryRun ? 'Dry run started' : `${action.title} started`);
    setConfirming(false);
    if (r.flow_id) history.push(`/hunts/${r.flow_id}`);
  };

  const start = async () => {
    try {
      if (mode === 'clients') await startOnClients();
      else await startHunt(condition);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  return (
    <Card>
      <CardHeader icon={action.icon} title={action.title} subtitle={action.description}
        actions={<Badge tone="neutral">{action.platforms}</Badge>} />
      <div className="tw:p-4 tw:space-y-5">
        {action.fields.length > 0 && (
          <section className="tw:space-y-3">
            {action.fields.map(f => (
              <label key={f.key} className="tw:block">
                <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">{f.label}{f.required && <span className="tw:text-bad"> *</span>}</span>
                {f.kind === 'textarea'
                  ? <Textarea rows={4} value={values[f.key] ?? ''} placeholder={f.placeholder} className={cn(f.mono && 'tw:font-mono tw:text-xs')}
                      onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))} />
                  : <Input value={values[f.key] ?? ''} placeholder={f.placeholder} className={cn(f.mono && 'tw:font-mono tw:text-xs')}
                      onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))} />}
                {f.help && <span className="tw:block tw:mt-1 tw:text-2xs tw:text-muted">{f.help}</span>}
              </label>
            ))}
          </section>
        )}

        <section className="tw:space-y-2">
          <div className="tw:text-xs tw:font-medium">Targets</div>
          <div className="tw:flex tw:flex-wrap tw:gap-1.5">
            {(['clients', 'labels', 'os', 'all'] as TargetMode[]).map(m => (
              <button key={m} type="button" onClick={() => setMode(m)}
                className={cn('tw:rounded-md tw:border tw:px-2.5 tw:py-1 tw:text-xs',
                  mode === m ? 'tw:border-accent tw:bg-accent-soft tw:text-accent tw:font-medium' : 'tw:border-line tw:hover:bg-hover')}>
                {m === 'clients' ? 'Specific clients' : m === 'labels' ? 'By label' : m === 'os' ? 'By OS' : 'All clients'}
              </button>
            ))}
          </div>
          {mode === 'clients' && <>
            <ClientPicker value={picked} onChange={setPicked} />
            <div className="tw:text-xs tw:text-muted">
              {picked.length === 0 ? 'Search and add at least one client.'
                : direct ? 'Runs right away on this client.'
                : `Runs as one hunt on ${picked.length} client${picked.length > 1 ? 's' : ''}${needsApproval ? ' after approval' : ''}.`}
            </div>
          </>}
          {mode === 'labels' && <TagInput value={labels} onChange={setLabels} tone="accent" placeholder="e.g. compromised, finance" />}
          {mode === 'os' && (
            <Select value={os} onChange={e => setOs(e.target.value)}>
              {Object.entries(OS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          )}
          {mode !== 'clients' && <>
            <div>
              <div className="tw:text-2xs tw:text-muted tw:mb-1">Exclude labels</div>
              <TagInput value={excluded} onChange={setExcluded} tone="bad" placeholder="Optional" />
            </div>
            <div className="tw:text-xs tw:text-muted">
              {missingLabels ? 'Add at least one label.' : <>Matches <span className="tw:font-semibold tw:text-fg">{estimate.data ?? '…'}</span> clients right now.</>}
            </div>
          </>}
        </section>

        <label className="tw:block">
          <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">
            Reason{!dryRun && <span className="tw:text-bad"> *</span>}
            <span className="tw:font-normal tw:text-muted"> · recorded in the audit log</span>
          </span>
          <Textarea rows={2} value={reason} onChange={e => setReason(e.target.value)}
            placeholder={dryRun ? 'Optional for dry runs' : 'Why this action is needed, e.g. case number or alert'} />
        </label>

        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3 tw:border-t tw:border-line tw:pt-4">
          {action.armParam
            ? <Switch checked={dryRun} onChange={setDryRun} label="Dry run: only report what would change" />
            : <span className="tw:text-2xs tw:text-muted">This action has no dry run mode.</span>}
          {needsApproval && <Badge tone="warn">Needs a second approver</Badge>}
          <Button className="tw:ml-auto" variant={dryRun ? 'primary' : 'danger'} icon={<Play className="tw:size-3.5" />}
            disabled={blocked} onClick={() => setConfirming(true)}>
            {dryRun ? 'Review dry run' : needsApproval ? 'Review and request approval' : 'Review and run'}
          </Button>
        </div>
        {!permitted && <div className="tw:text-2xs tw:text-bad">You need permission to start hunts.</div>}
      </div>

      {confirming && (
        <ConfirmResponseDialog action={action} params={params} targetText={fullTarget}
          hostCount={hostCount} dryRun={dryRun} reason={reason.trim()} needsApproval={needsApproval}
          onClose={() => setConfirming(false)} onConfirm={start} />
      )}
    </Card>
  );
}
