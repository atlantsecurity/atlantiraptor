// Server settings > Agent connections: agent certificates on the agent
// port (mutual TLS), the deployment certificate new agents enroll
// with, and blocked agents. The checks run in the server's TLS
// handshake (services/agentmtls); this page shows readiness and holds
// the controls.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { Ban, KeyRound, RotateCcw, ShieldCheck, ShieldOff, Unlock } from 'lucide-react';
import {
  KIND_LABEL, useAgentMtlsAction, useAgentMtlsStatus,
  type AgentMtlsMode, type AgentMtlsSettings, type AgentMtlsStatus,
} from '../../lib/agentmtls';
import { ApiError } from '../../lib/api';
import { fmtTime, timeAgo } from '../../lib/format';
import {
  Badge, Button, Card, CardHeader, ConfirmDialog, EmptyState, Mono, Progress, Segmented, Skeleton, Switch,
} from '../../ui/primitives';

const MODE_TEXT: Record<AgentMtlsMode, string> = {
  off: 'The agent port does not ask for certificates. Anyone who can reach it can talk to the server code, which still refuses anything not encrypted with an enrolled agent\'s key.',
  warn: 'Agents are asked for their certificate and everyone still gets in. Use this to see which agents are ready before you turn on Enforce.',
  enforce: 'Only this server\'s agents get past the TLS handshake. Scanners and attackers are dropped before any server code reads what they send.',
};

export default function AgentConnectionsPage() {
  const { data, isLoading, error } = useAgentMtlsStatus();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<ShieldCheck />} title="Agent connections are not available">{(error as Error)?.message}</EmptyState>;
  }
  return <AgentConnections status={data} />;
}

function AgentConnections({ status }: { status: AgentMtlsStatus }) {
  const act = useAgentMtlsAction();
  const s = status.settings;
  const busy = act.isPending;
  const [confirmEnforce, setConfirmEnforce] = useState<{ next: AgentMtlsSettings; count: number } | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);

  const save = (next: AgentMtlsSettings, force = false) => act.mutate({ action: 'settings', settings: next, force }, {
    onSuccess: () => { setConfirmEnforce(null); toast.success(next.mode === 'enforce' ? 'Agent certificates are enforced' : 'Agent connection settings saved'); },
    onError: e => {
      if (e instanceof ApiError && e.status === 409) {
        setConfirmEnforce({ next, count: status.would_refuse || 1 });
        return;
      }
      toast.error((e as Error).message);
    },
  });

  const c = status.counts;
  const pct = (n: number) => (c.seen ? (n / c.seen) * 100 : 0);
  const unavailable = status.unavailable || (status.disabled_by_env ? 'ATLANTIRAPTOR_DISABLE_AGENT_MTLS is set on the server' : '');

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-[980px]">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><ShieldCheck className="tw:size-5 tw:text-accent" />Agent connections</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">
            Mutual TLS on the agent port: every agent proves who it is with its own certificate before the server reads anything it sends.
            Messages stay end-to-end encrypted as before. Expose only the agent port to the internet and keep the console private;
            see <a className="tw:text-accent" href="https://atlantsecurity.github.io/atlantiraptor/deployment/internet-facing/" target="_blank" rel="noreferrer">Internet-facing agents</a>.
          </p>
        </div>

        {unavailable && (
          <div className="tw:rounded-md tw:border tw:border-warn tw:bg-warn-soft tw:px-3 tw:py-2 tw:text-xs">
            Agent certificates are off on this server: {unavailable}.
          </div>
        )}

        {status.console_exposed && (
          <div className="tw:rounded-md tw:border tw:border-line tw:bg-panel tw:px-3 tw:py-2 tw:text-xs tw:text-muted">
            The console listens on <Mono>{status.console_bind}</Mono>, not only on this server. If that address is reachable from the internet,
            limit it under <Link className="tw:text-accent" to="/network">Network access</Link>, or set <Mono>GUI.bind_address</Mono> to
            <Mono>127.0.0.1</Mono> and reach the console over a VPN or SSH tunnel.
          </div>
        )}

        <Card>
          <CardHeader icon={<ShieldCheck className="tw:size-4" />} title="Certificate check"
            actions={<Badge tone={status.effective_mode === 'enforce' ? 'ok' : status.effective_mode === 'warn' ? 'info' : 'neutral'} dot>
              {status.effective_mode === 'enforce' ? 'Enforced' : status.effective_mode === 'warn' ? 'Warn only' : 'Off'}
            </Badge>} />
          <div className="tw:px-4 tw:py-3 tw:space-y-3 tw:text-[13px]">
            <Segmented<AgentMtlsMode> size="md" value={s.mode}
              onChange={mode => !busy && mode !== s.mode && save({ ...s, mode })}
              options={[{ value: 'off', label: 'Off' }, { value: 'warn', label: 'Warn' }, { value: 'enforce', label: 'Enforce' }]} />
            <p className="tw:text-xs tw:text-muted">{MODE_TEXT[s.mode]}</p>

            {s.mode === 'off' ? (
              <p className="tw:text-2xs tw:text-faint">Turn on Warn to see which agents present a certificate.</p>
            ) : c.seen > 0 ? (
              <div className="tw:space-y-1.5">
                <Progress segments={[
                  { value: pct(c.own), tone: 'ok' },
                  { value: pct(c.new), tone: 'accent' },
                  { value: pct(c.legacy), tone: 'warn' },
                  { value: pct(c.none + c.other), tone: 'bad' },
                ]} />
                <div className="tw:flex tw:flex-wrap tw:gap-x-4 tw:gap-y-1 tw:text-2xs tw:text-muted">
                  <span><span className="tw:text-ok tw:font-medium">{c.own}</span> of {c.seen} agents seen in the last 24 hours present their own certificate</span>
                  {c.legacy > 0 && <span className="tw:text-warn">{c.legacy} only the deployment certificate</span>}
                  {c.none > 0 && <span className="tw:text-bad">{c.none} no certificate</span>}
                  {c.other > 0 && <span className="tw:text-bad">{c.other} a wrong certificate</span>}
                </div>
                <p className="tw:text-2xs tw:text-faint">
                  {status.would_refuse === 0
                    ? 'Every agent seen in the last 24 hours would get in with Enforce on.'
                    : `${status.would_refuse} agent${status.would_refuse === 1 ? '' : 's'} would be refused with Enforce on. Windows agents start presenting certificates when they upgrade to 1.0.8; reinstall the others with the commands under Deploy a client.`}
                  {' '}Counts start over when the server restarts.
                </p>
              </div>
            ) : (
              <p className="tw:text-2xs tw:text-faint">No agent has connected since the server started.</p>
            )}

            <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3 tw:pt-1">
              <div className="tw:rounded-md tw:border tw:border-line tw:p-3 tw:space-y-1">
                <Switch checked={s.allow_enrollment} disabled={busy} label="New agents can enroll"
                  onChange={v => save({ ...s, allow_enrollment: v })} />
                <p className="tw:text-2xs tw:text-muted">
                  New installs (GPO, Intune, MSI, install scripts) enroll by themselves with the deployment certificate in their configuration.
                  Turn this off to let only agents that already enrolled connect.
                </p>
              </div>
              <div className="tw:rounded-md tw:border tw:border-line tw:p-3 tw:space-y-1">
                <Switch checked={s.allow_legacy} disabled={busy} label="Accept older agents"
                  onChange={v => save({ ...s, allow_legacy: v })} />
                <p className="tw:text-2xs tw:text-muted">
                  Agents from before 1.0.8 can present only the shared deployment certificate, not one of their own.
                  They can't be blocked in the handshake. Turn this off once every agent has upgraded.
                </p>
              </div>
            </div>
            {s.updated ? <p className="tw:text-2xs tw:text-faint">Last changed by {s.updated_by} {fmtTime(s.updated)}</p> : null}
          </div>
        </Card>

        {status.not_ready.length > 0 && (
          <Card>
            <CardHeader icon={<ShieldOff className="tw:size-4" />} title="Agents without their own certificate"
              subtitle="Seen in the last 24 hours" />
            <div className="tw:divide-y tw:divide-line tw:max-h-80 tw:overflow-y-auto">
              {status.not_ready.map(a => (
                <div key={a.client_id} className="tw:px-4 tw:py-1.5 tw:text-xs tw:flex tw:flex-wrap tw:items-center tw:gap-x-3 tw:gap-y-0.5">
                  <Link to={`/host/${a.org_id && a.org_id !== 'root' ? `${a.client_id}-${a.org_id}` : a.client_id}`}
                    className="tw:font-medium tw:text-accent">{a.hostname || a.client_id}</Link>
                  {a.version && <span className="tw:text-muted">{a.version}</span>}
                  <span className={a.kind === 'legacy' ? 'tw:text-warn' : 'tw:text-bad'}>{KIND_LABEL[a.kind]}</span>
                  <span className="tw:text-faint tw:ml-auto">{a.remote} · {timeAgo(a.last_seen)}</span>
                </div>
              ))}
            </div>
          </Card>
        )}

        <Card>
          <CardHeader icon={<KeyRound className="tw:size-4" />} title="Deployment certificate"
            actions={<Button size="sm" icon={<RotateCcw className="tw:size-3.5" />} disabled={busy || !status.deployment}
              onClick={() => setConfirmRotate(true)}>Rotate…</Button>} />
          <div className="tw:px-4 tw:py-3 tw:space-y-2 tw:text-xs">
            <p className="tw:text-muted">
              Every client configuration from <Link className="tw:text-accent" to="/settings/deploy">Deploy a client</Link> (MSI, Intune package, install scripts)
              carries this certificate. A new agent uses it to sign a certificate for its own key and enrolls with no manual steps.
              Once enrolled, agents are recognized by their own key, so rotating never affects them.
            </p>
            {status.deployment ? (
              <p className="tw:text-faint tw:break-all">
                Serial <Mono>{status.deployment.serial}</Mono> · {status.deployment.from_config
                  ? 'from the server configuration'
                  : `issued ${fmtTime(status.deployment.created)}${status.deployment.created_by ? ` by ${status.deployment.created_by}` : ''}`}
              </p>
            ) : <p className="tw:text-bad">This server has no deployment certificate (its configuration has no CA key).</p>}
          </div>
        </Card>

        <Card>
          <CardHeader icon={<Ban className="tw:size-4" />} title="Blocked agents"
            subtitle="Block an agent from its host page (More actions > Block agent)" />
          {status.blocked.length === 0 ? (
            <div className="tw:px-4 tw:py-4 tw:text-xs tw:text-faint">No agent is blocked.</div>
          ) : (
            <div className="tw:divide-y tw:divide-line">
              {status.blocked.map(b => (
                <div key={b.client_id} className="tw:px-4 tw:py-2 tw:text-xs tw:flex tw:flex-wrap tw:items-center tw:gap-x-3 tw:gap-y-1">
                  <div className="tw:min-w-0 tw:flex-1">
                    <div className="tw:font-medium">{b.hostname || b.client_id} <Mono className="tw:text-faint">{b.client_id}</Mono></div>
                    <div className="tw:text-faint">Blocked by {b.by} {timeAgo(b.time)}{b.reason ? `: ${b.reason}` : ''}</div>
                  </div>
                  <Button size="sm" icon={<Unlock className="tw:size-3.5" />} disabled={busy}
                    onClick={() => act.mutate({ action: 'unblock', client_id: b.client_id }, {
                      onSuccess: () => toast.success(`${b.hostname || b.client_id} can connect again`),
                      onError: e => toast.error((e as Error).message),
                    })}>Unblock</Button>
                </div>
              ))}
            </div>
          )}
        </Card>

        {status.rejections.length > 0 && (
          <Card>
            <CardHeader icon={<ShieldOff className="tw:size-4" />} title="Recent refused or unrecognized connections"
              subtitle="At most one entry a minute per agent or address; kept until the server restarts" />
            <div className="tw:divide-y tw:divide-line tw:max-h-72 tw:overflow-y-auto">
              {status.rejections.map((r, i) => (
                <div key={i} className="tw:px-4 tw:py-1.5 tw:text-xs tw:flex tw:flex-wrap tw:gap-x-3">
                  <Badge tone={r.refused ? 'bad' : 'warn'}>{r.refused ? 'Refused' : 'Allowed (Warn)'}</Badge>
                  <span>{r.reason}</span>
                  {r.client_id && <Mono className="tw:text-faint">{r.client_id}</Mono>}
                  <span className="tw:text-faint tw:ml-auto">{r.remote} · {timeAgo(r.time)}</span>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>

      <ConfirmDialog open={!!confirmEnforce} onOpenChange={v => !v && setConfirmEnforce(null)} danger loading={busy}
        title="Enforce agent certificates now?" confirmLabel="Enforce anyway"
        onConfirm={() => confirmEnforce && save(confirmEnforce.next, true)}>
        {confirmEnforce?.count ?? 0} agent{confirmEnforce?.count === 1 ? '' : 's'} seen in the last 24 hours would be refused and
        stop reporting until they are upgraded or reinstalled. They are listed under Agents without their own certificate.
      </ConfirmDialog>

      <ConfirmDialog open={confirmRotate} onOpenChange={setConfirmRotate} danger loading={busy}
        title="Rotate the deployment certificate?" confirmLabel="Rotate"
        onConfirm={() => act.mutate({ action: 'rotate' }, {
          onSuccess: () => { setConfirmRotate(false); toast.success('New deployment certificate issued. Download new installers from Deploy a client.'); },
          onError: e => { setConfirmRotate(false); toast.error((e as Error).message); },
        })}>
        Enrolled agents keep working. New installs need a client configuration made after this (download the MSI configuration,
        Intune package and install scripts again from Deploy a client). Installers made before now stop enrolling new computers
        while Enforce is on, and older agents that present only the old deployment certificate are refused.
      </ConfirmDialog>
    </div>
  );
}
