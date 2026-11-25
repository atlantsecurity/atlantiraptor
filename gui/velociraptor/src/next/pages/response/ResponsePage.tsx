// Fleet response: pick an action, pick targets, confirm, and the action
// runs as a hunt across every matching client. Progress and per-client
// results live in the hunt; recent actions are listed below.
import { useMemo, useState } from 'react';
import { useHistory, useLocation, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Play, Siren, X } from 'lucide-react';
import {
  runArtifacts, useClient, useCreateHunt, useEstimateHunt, usePermission, type CreateHuntRequest,
} from '../../lib/queries';
import type { HuntCondition } from '../../lib/types';
import { Badge, Button, Card, CardHeader, Input, Select, Switch, Textarea, cn } from '../../ui/primitives';
import { TagInput } from '../hunts/TagInput';
import { ACTIONS, GROUPS, RESPONSE_TAG, type ResponseAction } from './actions';
import { ConfirmResponseDialog } from './ConfirmResponseDialog';
import { ResponseHistory } from './ResponseHistory';

type TargetMode = 'all' | 'labels' | 'os' | 'client';
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
  const canRun = clientId ? canCollect : canHunt;

  return (
    <div className="tw:flex-1 tw:overflow-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-5">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Siren className="tw:size-5 tw:text-bad" />Response</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">
            Send a response action to many clients at once. Each action runs as a hunt, so hosts that are offline act when they next check in.
          </p>
        </div>
        <div className="tw:grid tw:grid-cols-1 tw:lg:grid-cols-[280px_1fr] tw:gap-4 tw:items-start">
          <ActionList selected={action.id}
            onSelect={id => history.push(`/response/${id}${clientId ? `?client=${clientId}` : ''}`)} />
          <ActionForm key={`${action.id}-${clientId}`} action={action} canRun={canRun} clientId={clientId} prefill={query} />
        </div>
        <ResponseHistory />
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
  const hostname = client?.os_info?.hostname || clientId;
  const [values, setValues] = useState(() => initialValues(action, prefill));
  const [mode, setMode] = useState<TargetMode>(clientId ? 'client' : 'labels');
  const [labels, setLabels] = useState<string[]>([]);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [os, setOs] = useState('WINDOWS');
  const [dryRun, setDryRun] = useState(!!action.armParam);
  const [confirming, setConfirming] = useState(false);

  const condition: HuntCondition = useMemo(() => {
    const c: HuntCondition = {};
    if (mode === 'labels' && labels.length) c.labels = { label: labels };
    if (mode === 'os') c.os = { os };
    if (excluded.length) c.excluded_labels = { label: excluded };
    return c;
  }, [mode, labels, excluded, os]);
  const missingLabels = mode === 'labels' && labels.length === 0;
  const estimate = useEstimateHunt(condition, 'all', !missingLabels && mode !== 'client');
  const hostCount = mode === 'client' ? 1 : missingLabels ? undefined : estimate.data;

  const missing = action.fields.filter(f => f.required && !(values[f.key] ?? '').trim());
  const blocked = !canRun || missingLabels || missing.length > 0;

  const params: Record<string, string> = useMemo(() => {
    const p: Record<string, string> = { ...action.fixed };
    for (const f of action.fields) {
      const v = (values[f.key] ?? '').trim();
      if (v) p[f.key] = f.kind === 'textarea' ? values[f.key] : v;
    }
    if (action.armParam) p[action.armParam] = dryRun ? 'N' : 'Y';
    return p;
  }, [action, values, dryRun]);

  const targetText = mode === 'client' ? `Only ${hostname} (${clientId})`
    : mode === 'all' ? 'All clients'
    : mode === 'os' ? `All ${OS_LABEL[os]} clients`
    : `Clients labelled ${labels.join(', ') || '…'}`;
  const fullTarget = excluded.length && mode !== 'client' ? `${targetText}, except ${excluded.join(', ')}` : targetText;

  // A single host is handled as a direct collection rather than a hunt.
  const startOnClient = async () => {
    try {
      const per = Object.fromEntries(action.artifacts.map(a => [a, params]));
      const r = await runArtifacts(clientId, action.artifacts, per, true);
      toast.success(dryRun ? 'Dry run started' : `${action.title} started on ${hostname}`);
      setConfirming(false);
      if (r.flow_id) history.push(`/collected/${clientId}/${r.flow_id}`);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const start = async () => {
    if (mode === 'client') return startOnClient();
    const env = Object.entries(params).map(([key, value]) => ({ key, value }));
    const req: CreateHuntRequest = {
      hunt_description: `Response: ${action.summary(values)}${dryRun ? ' (dry run)' : ''}`,
      tags: [RESPONSE_TAG, action.id, ...(dryRun ? ['dry-run'] : [])],
      start_request: {
        artifacts: action.artifacts,
        specs: action.artifacts.map(artifact => ({ artifact, parameters: { env } })),
        urgent: true,
      },
      condition,
      state: 2,
    };
    try {
      const r = await create.mutateAsync(req);
      toast.success(dryRun ? 'Dry run started' : `${action.title} started`);
      setConfirming(false);
      if (r.flow_id) history.push(`/hunts/${r.flow_id}`);
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
          {mode === 'client' ? (
            <div className="tw:flex tw:items-center tw:gap-2 tw:rounded-md tw:border tw:border-accent tw:bg-accent-soft tw:px-3 tw:py-2 tw:text-xs">
              <span className="tw:flex-1">Only this host: <b>{hostname}</b> <span className="tw:font-mono tw:text-faint">{clientId}</span></span>
              <button type="button" className="tw:flex tw:items-center tw:gap-1 tw:text-muted tw:hover:text-fg"
                onClick={() => history.push(`/response/${action.id}`)}>
                <X className="tw:size-3.5" />Target the fleet instead
              </button>
            </div>
          ) : <>
          <div className="tw:flex tw:flex-wrap tw:gap-1.5">
            {(['labels', 'os', 'all'] as TargetMode[]).map(m => (
              <button key={m} type="button" onClick={() => setMode(m)}
                className={cn('tw:rounded-md tw:border tw:px-2.5 tw:py-1 tw:text-xs',
                  mode === m ? 'tw:border-accent tw:bg-accent-soft tw:text-accent tw:font-medium' : 'tw:border-line tw:hover:bg-hover')}>
                {m === 'labels' ? 'By label' : m === 'os' ? 'By OS' : 'All clients'}
              </button>
            ))}
          </div>
          {mode === 'labels' && <TagInput value={labels} onChange={setLabels} tone="accent" placeholder="e.g. compromised, finance" />}
          {mode === 'os' && (
            <Select value={os} onChange={e => setOs(e.target.value)}>
              {Object.entries(OS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          )}
          <div>
            <div className="tw:text-2xs tw:text-muted tw:mb-1">Exclude labels</div>
            <TagInput value={excluded} onChange={setExcluded} tone="bad" placeholder="Optional" />
          </div>
          <div className="tw:text-xs tw:text-muted">
            {missingLabels ? 'Add at least one label.' : <>Matches <span className="tw:font-semibold tw:text-fg">{estimate.data ?? '…'}</span> clients right now.</>}
          </div>
          </>}
        </section>

        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3 tw:border-t tw:border-line tw:pt-4">
          {action.armParam
            ? <Switch checked={dryRun} onChange={setDryRun} label="Dry run: only report what would change" />
            : <span className="tw:text-2xs tw:text-muted">This action has no dry run mode.</span>}
          <Button className="tw:ml-auto" variant={dryRun ? 'primary' : 'danger'} icon={<Play className="tw:size-3.5" />}
            disabled={blocked} onClick={() => setConfirming(true)}>
            {dryRun ? 'Review dry run' : 'Review and run'}
          </Button>
        </div>
        {!canRun && <div className="tw:text-2xs tw:text-bad">You need permission to start hunts.</div>}
      </div>

      {confirming && (
        <ConfirmResponseDialog action={action} params={params} targetText={fullTarget}
          hostCount={hostCount} dryRun={dryRun}
          onClose={() => setConfirming(false)} onConfirm={start} />
      )}
    </Card>
  );
}
