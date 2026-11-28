// Admin > Server updates > Agent updates: after the server updates
// itself, it upgrades Windows agents to the same release, a canary
// group first. The rollout runs on the server; this card shows where it
// is and holds the settings.
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { Laptop, Pause, Play, RotateCcw } from 'lucide-react';
import {
  useAgentUpdateAction, useAgentUpdateStatus,
  type AgentUpdateSettings, type AgentUpdateStatus,
} from '../../lib/agentupdates';
import { Badge, Button, Card, CardHeader, Field, Input, Mono, Progress, Select, Skeleton, Switch } from '../../ui/primitives';

const CANARY_HOURS = [0, 1, 4, 12, 24, 48, 72, 168];
const when = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleString() : 'never');
const hoursLabel = (h: number) => (h === 0 ? 'no wait' : h < 24 ? `${h} hour${h === 1 ? '' : 's'}` : `${h / 24} day${h === 24 ? '' : 's'}`);

const STATE_BADGE: Record<AgentUpdateStatus['state'], { tone: 'neutral' | 'ok' | 'warn' | 'bad' | 'info'; label: string }> = {
  idle: { tone: 'neutral', label: 'Idle' },
  disabled: { tone: 'neutral', label: 'Off' },
  error: { tone: 'bad', label: 'Problem' },
  'rolling out': { tone: 'info', label: 'Rolling out' },
  paused: { tone: 'warn', label: 'Paused' },
  done: { tone: 'ok', label: 'All agents current' },
};

export default function AgentUpdates() {
  const { data, isLoading, error } = useAgentUpdateStatus();
  if (isLoading) return <Card><div className="tw:p-4"><Skeleton className="tw:h-24" /></div></Card>;
  if (error || !data) {
    return (
      <Card>
        <CardHeader icon={<Laptop className="tw:size-4" />} title="Agent updates" />
        <div className="tw:px-4 tw:py-3 tw:text-xs tw:text-muted">{(error as Error)?.message ?? 'Not available.'}</div>
      </Card>
    );
  }
  return <AgentUpdatesCard status={data} />;
}

function AgentUpdatesCard({ status }: { status: AgentUpdateStatus }) {
  const act = useAgentUpdateAction();
  const s = status.settings;
  const [draft, setDraft] = useState<AgentUpdateSettings>(s);
  useEffect(() => setDraft(s), [s.enabled, s.pinned_version, s.canary_percent, s.canary_hours, s.exclude_label]); // eslint-disable-line react-hooks/exhaustive-deps

  const c = status.counts;
  const busy = act.isPending;
  const dirty = (draft.pinned_version ?? '') !== (s.pinned_version ?? '') || draft.canary_percent !== s.canary_percent ||
    draft.canary_hours !== s.canary_hours || draft.exclude_label !== s.exclude_label;

  const run = (p: Parameters<typeof act.mutate>[0], ok: string) => act.mutate(p, {
    onSuccess: () => toast.success(ok),
    onError: e => toast.error((e as Error).message),
  });
  const save = (next: AgentUpdateSettings, ok = 'Agent update settings saved') => run({ action: 'settings', settings: next }, ok);

  const badge = STATE_BADGE[status.state] ?? STATE_BADGE.idle;
  const pct = (n: number) => (c.windows ? (n / c.windows) * 100 : 0);
  const versions = Object.entries(c.versions ?? {}).sort((a, b) => b[1] - a[1]);
  const otherPlatforms = Object.entries(c.platforms ?? {}).filter(([os]) => os !== 'windows');

  return (
    <Card>
      <CardHeader icon={<Laptop className="tw:size-4" />} title="Agent updates"
        actions={<Switch checked={s.enabled} disabled={busy}
          onChange={v => save({ ...s, enabled: v }, v ? 'Automatic agent upgrades are on' : 'Automatic agent upgrades are off')}
          label={s.enabled ? 'On' : 'Off'} />} />
      <div className="tw:px-4 tw:py-3 tw:space-y-3 tw:text-[13px]">
        <p className="tw:text-2xs tw:text-muted">
          After this server updates, it upgrades Windows agents to {s.pinned_version ? 'the pinned version' : 'the same release'}:
          a canary group first, then every other agent once the canary has run the new version without problems.
          Each agent checks the Atlant Security signature before installing and goes back to its previous version if the new one does not stay running.
        </p>

        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <Badge tone={badge.tone} dot>{badge.label}</Badge>
          {status.target && <span>Target <span className="tw:font-medium">{status.target}</span>{s.pinned_version ? ' (pinned)' : ''}</span>}
          {status.phase === 'canary' && (
            <span className="tw:text-muted">
              Canary: {c.canary_done} of {c.canary} upgraded{status.canary_until ? `, everyone else from ${when(status.canary_until)}` : ''}
            </span>
          )}
          {status.phase === 'all' && status.state !== 'done' && <span className="tw:text-muted">Upgrading every Windows agent</span>}
        </div>

        {status.reason && <p className="tw:text-xs tw:text-muted">{status.reason}</p>}
        {status.disabled_by_env && <p className="tw:text-xs tw:text-warn">ATLANTIRAPTOR_DISABLE_AGENT_UPDATE is set on the server: agent upgrades are off.</p>}
        {status.paused_reason && (
          <div className="tw:rounded-md tw:border tw:border-warn tw:bg-warn-soft tw:px-3 tw:py-2 tw:text-xs tw:flex tw:flex-wrap tw:items-center tw:gap-2">
            <Pause className="tw:size-3.5 tw:text-warn" /><span className="tw:flex-1">{status.paused_reason}</span>
            <Button size="sm" icon={<Play className="tw:size-3.5" />} disabled={busy}
              onClick={() => run({ action: 'resume' }, 'Rollout resumed for every agent')}>Resume for everyone</Button>
          </div>
        )}
        {status.last_error && <p className="tw:text-xs tw:text-bad">{status.last_error}</p>}

        {c.windows > 0 && (
          <div className="tw:space-y-1.5">
            <Progress segments={[
              { value: pct(c.up_to_date), tone: 'ok' },
              { value: pct(c.upgrading + c.retrying), tone: 'accent' },
              { value: pct(c.failed), tone: 'bad' },
              { value: pct(c.waiting + c.offline + c.excluded), tone: 'muted' },
            ]} />
            <div className="tw:flex tw:flex-wrap tw:gap-x-4 tw:gap-y-1 tw:text-2xs tw:text-muted">
              <span><span className="tw:text-ok tw:font-medium">{c.up_to_date}</span> of {c.windows} Windows agents current</span>
              {c.upgrading > 0 && <span>{c.upgrading} upgrading</span>}
              {c.retrying > 0 && <span>{c.retrying} retrying</span>}
              {c.failed > 0 && <span className="tw:text-bad">{c.failed} failed</span>}
              {c.waiting > 0 && <span>{c.waiting} waiting</span>}
              {c.offline > 0 && <span>{c.offline} offline (upgraded when they reconnect)</span>}
              {c.excluded > 0 && <span>{c.excluded} opted out</span>}
              {c.newer > 0 && <span>{c.newer} newer than the target</span>}
            </div>
          </div>
        )}

        {versions.length > 0 && (
          <div>
            <div className="tw:text-2xs tw:text-muted tw:mb-1">Windows agents by version</div>
            <div className="tw:flex tw:flex-wrap tw:gap-1.5">
              {versions.map(([v, n]) => (
                <Badge key={v} tone={v === status.target ? 'ok' : 'neutral'}>{v} · {n}</Badge>
              ))}
            </div>
          </div>
        )}
        {otherPlatforms.length > 0 && (
          <p className="tw:text-2xs tw:text-muted">
            Not upgraded automatically: {otherPlatforms.map(([os, n]) => `${n} ${os === 'darwin' ? 'macOS' : os === 'linux' ? 'Linux' : os}`).join(', ')} agent{c.unsupported === 1 ? '' : 's'}.
            Releases carry no signed Linux or macOS binaries yet; reinstall those with the commands under Clients &gt; Deploy a client.
          </p>
        )}

        {status.failed.length > 0 && (
          <div className="tw:space-y-1">
            <div className="tw:flex tw:items-center tw:gap-2">
              <span className="tw:text-2xs tw:text-muted tw:flex-1">Agents whose upgrade failed</span>
              <Button size="sm" icon={<RotateCcw className="tw:size-3.5" />} disabled={busy}
                onClick={() => run({ action: 'retry_failed' }, 'Failed agents will be tried again')}>Retry failed</Button>
            </div>
            <div className="tw:rounded-md tw:border tw:border-line tw:divide-y tw:divide-line tw:max-h-56 tw:overflow-y-auto">
              {status.failed.map(f => (
                <div key={f.org_id + f.client_id} className="tw:px-3 tw:py-1.5 tw:text-xs">
                  <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
                    <Link to={`/host/${f.client_id}`} className="tw:font-medium tw:text-accent">{f.hostname || f.client_id}</Link>
                    <span className="tw:text-muted">{f.version}</span>
                    <span className="tw:text-faint">{f.attempts} attempt{f.attempts === 1 ? '' : 's'}</span>
                    {f.org_id !== 'root' && <span className="tw:text-faint">org {f.org_id}</span>}
                  </div>
                  <div className="tw:text-bad tw:break-words">{f.error}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3 tw:pt-1">
          <Field label="Version" hint="Empty follows this server's release. A pinned version is rolled out exactly, also downwards.">
            <Input value={draft.pinned_version ?? ''} placeholder={status.server_version || 'e.g. 1.0.4'} disabled={busy}
              onChange={e => setDraft({ ...draft, pinned_version: e.target.value })} />
          </Field>
          <Field label="Opt-out label" hint="Agents with this label are never upgraded automatically.">
            <Input value={draft.exclude_label} disabled={busy} onChange={e => setDraft({ ...draft, exclude_label: e.target.value })} />
          </Field>
          <Field label="Canary group" hint="Share of Windows agents that get a new version first (at least one). 0 upgrades everyone at once.">
            <Select value={draft.canary_percent} disabled={busy} onChange={e => setDraft({ ...draft, canary_percent: Number(e.target.value) })}>
              {[...new Set([0, 1, 5, 10, 25, 50, 100, draft.canary_percent])].sort((a, b) => a - b)
                .map(p => <option key={p} value={p}>{p}%</option>)}
            </Select>
          </Field>
          <Field label="Wait before everyone else" hint="How long the canary runs the new version first.">
            <Select value={draft.canary_hours} disabled={busy} onChange={e => setDraft({ ...draft, canary_hours: Number(e.target.value) })}>
              {[...new Set([...CANARY_HOURS, draft.canary_hours])].sort((a, b) => a - b)
                .map(h => <option key={h} value={h}>{hoursLabel(h)}</option>)}
            </Select>
          </Field>
        </div>
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <Button variant="primary" disabled={!dirty || busy} loading={busy} onClick={() => save(draft)}>Save</Button>
          {dirty && <Button disabled={busy} onClick={() => setDraft(s)}>Cancel</Button>}
          <Button disabled={busy || !s.enabled} onClick={() => run({ action: 'run' }, 'Checking agents now')}>Check agents now</Button>
          <span className="tw:text-2xs tw:text-faint tw:ml-auto">
            Last round {when(status.last_tick)}{status.next_tick ? ` · next ${when(status.next_tick)}` : ''}
          </span>
        </div>

        {status.binary && (
          <p className="tw:text-2xs tw:text-faint tw:break-all">
            Hosting {status.binary.version} as tool <Mono>{status.tool_name}</Mono> from {status.binary.source}, signed by {status.binary.signer},
            SHA-256 <Mono>{status.binary.sha256}</Mono>. Agents run <Mono>{status.artifact_name}</Mono>.
          </p>
        )}
        {s.updated ? <p className="tw:text-2xs tw:text-faint">Settings last changed by {s.updated_by} {when(s.updated)}</p> : null}
      </div>
    </Card>
  );
}
