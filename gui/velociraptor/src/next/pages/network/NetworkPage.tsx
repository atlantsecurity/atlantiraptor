// Admin > Network access: which addresses may reach the console and the
// integration API. Enforced by the server; this page edits the lists.
import { useState } from 'react';
import { toast } from 'sonner';
import { Globe, Network, Save, ShieldAlert } from 'lucide-react';
import { coveredBy, entryProblem, splitEntries, useNetworkPolicy, useSaveNetworkPolicy, type NetworkPolicy, type NetworkView } from '../../lib/network';
import { Badge, Button, Card, CardHeader, ConfirmDialog, EmptyState, Mono, Skeleton, Switch, Textarea, cn } from '../../ui/primitives';

export default function NetworkPage() {
  const { data, isLoading, error } = useNetworkPolicy();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<Network />} title="Network access is not available">{(error as Error)?.message}</EmptyState>;
  }
  return <Editor key={data.policy.updated ?? 0} view={data} />;
}

interface Draft { enabled: boolean; text: string }

const toDraft = (l: { enabled: boolean; entries: string[] }): Draft => ({ enabled: l.enabled, text: (l.entries ?? []).join('\n') });

function Editor({ view }: { view: NetworkView }) {
  const save = useSaveNetworkPolicy();
  const [consoleList, setConsole] = useState<Draft>(toDraft(view.policy.console ?? { enabled: false, entries: [] }));
  const [apiList, setApi] = useState<Draft>(toDraft(view.policy.api ?? { enabled: false, entries: [] }));
  const [confirming, setConfirming] = useState<string | null>(null);

  const policy: NetworkPolicy = {
    console: { enabled: consoleList.enabled, entries: splitEntries(consoleList.text) },
    api: { enabled: apiList.enabled, entries: splitEntries(apiList.text) },
  };
  const problems = [...policy.console.entries, ...policy.api.entries].map(entryProblem).filter(Boolean) as string[];
  const ownCovered = view.your_ip_is_local || !policy.console.enabled || coveredBy(view.your_ip, policy.console.entries) !== false;

  const submit = (confirm = false) => save.mutate({ policy, confirm_lockout: confirm }, {
    onSuccess: () => { toast.success('Network access saved'); setConfirming(null); },
    onError: e => {
      const err = e as Error & { status?: number };
      if (err.status === 409 && !confirm) setConfirming(err.message);
      else toast.error(err.message);
    },
  });

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Network className="tw:size-5 tw:text-accent" />Network access</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Allow only listed addresses to reach the console or the integration API. Each list is off until you turn it on.
              This server itself (localhost) is always allowed.
            </p>
          </div>
          <Button variant="primary" icon={<Save className="tw:size-3.5" />} loading={save.isPending} disabled={problems.length > 0}
            onClick={() => submit(false)}>Save</Button>
        </div>

        <Card>
          <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3 tw:px-4 tw:py-3 tw:text-[13px]">
            <Globe className="tw:size-4 tw:text-muted" />
            <span>Your address: <Mono className="tw:font-medium">{view.your_ip || 'unknown'}</Mono></span>
            {view.your_ip_is_local ? <Badge tone="ok">this server: always allowed</Badge>
              : ownCovered ? <Badge tone="ok">allowed by the console list</Badge>
              : <Badge tone="bad">not in the console list: saving would lock you out</Badge>}
            {view.proxy_warning && <Badge tone="bad">Requests arrive from localhost through a proxy: set GUI.forwarded_proxy_header in the server config, or the lists can't tell clients apart</Badge>}
            {view.break_glass_active && <Badge tone="warn">ATLANTIRAPTOR_DISABLE_ALLOWLIST is set: lists are not enforced</Badge>}
            {view.policy.updated ? <span className="tw:ml-auto tw:text-2xs tw:text-muted">Last changed by {view.policy.updated_by} {new Date(view.policy.updated * 1000).toLocaleString()}</span> : null}
          </div>
        </Card>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          <ListCard title="Console" subtitle="The web console, its sign-in pages and its API (used by analysts' browsers)."
            draft={consoleList} onChange={setConsole} yourIp={view.your_ip} />
          <ListCard title="Integration API" subtitle="/api/atl/v1, used by SIEM and SOAR tools with API keys. Each key can also have its own list (Admin › API keys)."
            draft={apiList} onChange={setApi} yourIp={view.your_ip} />
        </div>

        {problems.length > 0 && <div className="tw:text-xs tw:text-bad">{problems.join(' · ')}</div>}

        <Card>
          <CardHeader icon={<ShieldAlert className="tw:size-4" />} title="If you lock yourself out" />
          <div className="tw:px-4 tw:pb-4 tw:text-xs tw:text-muted tw:space-y-1">
            <p>Open the console on the server itself (https://127.0.0.1:{window.location.port || '8889'}), which is always allowed, and fix the list.</p>
            <p>Or restart the server with the environment variable <Mono>ATLANTIRAPTOR_DISABLE_ALLOWLIST=1</Mono>, which turns every list off until it is removed.</p>
            {view.static_cidrs && view.static_cidrs.length > 0 && (
              <p>The server config file also limits the console to: <Mono>{view.static_cidrs.join(', ')}</Mono> (GUI.allowed_cidr). That list is applied first.</p>
            )}
            <p>Refused attempts are written to the audit log as <Mono>network_denied</Mono>. These lists cover the console and the integration API; endpoint agents connect on a separate port and are not affected.</p>
          </div>
        </Card>
      </div>

      <ConfirmDialog open={!!confirming} onOpenChange={v => !v && setConfirming(null)} danger
        title="Save anyway?" confirmLabel="Save and accept the risk" loading={save.isPending}
        onConfirm={() => submit(true)}>
        {confirming} You can still get in from the server itself (localhost).
      </ConfirmDialog>
    </div>
  );
}

function ListCard({ title, subtitle, draft, onChange, yourIp }: {
  title: string; subtitle: string; draft: Draft; onChange: (d: Draft) => void; yourIp: string;
}) {
  const entries = splitEntries(draft.text);
  return (
    <Card>
      <CardHeader icon={<Network className="tw:size-4" />} title={title} subtitle={subtitle}
        actions={<Switch checked={draft.enabled} onChange={v => onChange({ ...draft, enabled: v })} label={draft.enabled ? 'Enforced' : 'Off'} />} />
      <div className={cn('tw:px-4 tw:pb-4 tw:space-y-2', !draft.enabled && 'tw:opacity-60')}>
        <Textarea rows={6} className="tw:font-mono tw:text-xs" value={draft.text}
          onChange={e => onChange({ ...draft, text: e.target.value })}
          placeholder={'One per line, for example:\n10.0.0.0/8\n192.0.2.15\n2001:db8::/32'} />
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:text-2xs tw:text-muted">
          <span>{entries.length} entr{entries.length === 1 ? 'y' : 'ies'}</span>
          {yourIp && !entries.includes(yourIp) && (
            <button type="button" className="tw:text-accent tw:hover:underline"
              onClick={() => onChange({ ...draft, text: [...entries, yourIp].join('\n') })}>Add my address ({yourIp})</button>
          )}
          {draft.enabled && entries.length === 0 && <span className="tw:text-warn">Empty: only this server itself is allowed.</span>}
        </div>
      </div>
    </Card>
  );
}
