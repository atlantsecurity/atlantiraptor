// One alert with its drill-down actions: the client, the source event,
// triage, and response steps scoped to that single host.
import { useState } from 'react';
import { Link, useHistory } from 'react-router-dom';
import { Briefcase, ChevronDown, ChevronRight, FileSearch, FileX2, Laptop, ShieldAlert, Skull, Zap } from 'lucide-react';
import { AddToCaseDialog } from '../../cases/AddToCaseDialog';
import { useClient } from '../../../lib/queries';
import { fmtTime, timeAgo } from '../../../lib/format';
import { Badge, Button, Mono, Tooltip, cn } from '../../../ui/primitives';
import { detailEntries, sourceLink, SEVERITY_TONE, type Alert } from './model';

function respondUrl(action: string, clientId: string, prefill: Record<string, string> = {}): string {
  const q = new URLSearchParams({ client: clientId, ...prefill });
  return `/response/${action}?${q.toString()}`;
}

function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v, null, 2);
  return String(v);
}

export function AlertRow({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState(false);
  const [caseOpen, setCaseOpen] = useState(false);
  const history = useHistory();
  const { data: client } = useClient(alert.clientId || undefined);
  const host = client?.os_info?.hostname || alert.clientId || 'server';
  const source = sourceLink(alert);
  const path = typeof alert.data.path === 'string' ? alert.data.path : '';

  return (
    <div className={cn(open && 'tw:bg-hover/40')}>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="tw:flex tw:w-full tw:items-center tw:gap-3 tw:px-4 tw:py-2.5 tw:text-left tw:hover:bg-hover">
        {open ? <ChevronDown className="tw:size-3.5 tw:text-faint tw:shrink-0" /> : <ChevronRight className="tw:size-3.5 tw:text-faint tw:shrink-0" />}
        <Badge tone={SEVERITY_TONE[alert.severity]} className="tw:w-[68px] tw:justify-center tw:capitalize tw:shrink-0">{alert.severity}</Badge>
        <div className="tw:min-w-0 tw:flex-1">
          <div className="tw:text-[13px] tw:font-medium tw:truncate">{alert.rule}</div>
          <div className="tw:text-2xs tw:text-faint tw:truncate">
            {host}{alert.source ? ` · ${alert.source}` : ''}{alert.artifact ? ` · ${alert.artifact}` : ''}
          </div>
        </div>
        <Tooltip content={fmtTime(alert.time)}>
          <span className="tw:text-2xs tw:text-faint tw:shrink-0 tw:w-20 tw:text-right">{timeAgo(alert.time)}</span>
        </Tooltip>
      </button>

      {open && (
        <div className="tw:px-4 tw:pb-4 tw:pl-11 tw:space-y-3">
          {alert.description && <p className="tw:text-xs tw:text-muted">{alert.description}</p>}

          <div className="tw:flex tw:flex-wrap tw:gap-1.5">
            {alert.clientId && (
              <Button size="sm" variant="secondary" icon={<Laptop className="tw:size-3.5" />}
                onClick={() => history.push(`/host/${alert.clientId}`)}>Open {host}</Button>
            )}
            {source && (
              <Button size="sm" variant="secondary" icon={<FileSearch className="tw:size-3.5" />}
                onClick={() => history.push(source)}>View source event</Button>
            )}
            {alert.clientId && (
              <Button size="sm" variant="secondary" icon={<Zap className="tw:size-3.5" />}
                onClick={() => history.push(`/host/${alert.clientId}`)}>Triage host</Button>
            )}
            {alert.clientId && (
              <Button size="sm" variant="secondary" icon={<ShieldAlert className="tw:size-3.5" />}
                onClick={() => history.push(respondUrl('quarantine', alert.clientId))}>Isolate host…</Button>
            )}
            {alert.clientId && path && (
              <Button size="sm" variant="secondary" icon={<FileX2 className="tw:size-3.5" />}
                onClick={() => history.push(respondUrl('delete', alert.clientId, { Glob: path.replace(/\\/g, '/') }))}>Delete file…</Button>
            )}
            {alert.clientId && (
              <Button size="sm" variant="secondary" icon={<Skull className="tw:size-3.5" />}
                onClick={() => history.push(respondUrl('kill', alert.clientId))}>Kill process…</Button>
            )}
            <Button size="sm" variant="primary" icon={<Briefcase className="tw:size-3.5" />}
              onClick={() => setCaseOpen(true)}>Add to case…</Button>
          </div>
          {caseOpen && (
            <AddToCaseDialog onClose={() => setCaseOpen(false)}
              suggestedTitle={`${alert.rule} on ${host}`}
              suggestedSeverity={alert.severity === 'info' ? 'low' : alert.severity}
              item={{
                kind: 'alert', ref: alert.key, clientId: alert.clientId || undefined,
                label: `${alert.rule} on ${host} (${fmtTime(alert.time)})`,
                data: { name: alert.name, time: alert.time?.toISOString(), artifact: alert.artifact, ...alert.data },
              }} />
          )}

          <dl className="tw:grid tw:grid-cols-[120px_1fr] tw:gap-x-3 tw:gap-y-1 tw:text-xs">
            <dt className="tw:text-muted">Alert</dt><dd className="tw:break-all">{alert.name}</dd>
            <dt className="tw:text-muted">Raised</dt><dd>{fmtTime(alert.time)}</dd>
            {alert.clientId && <><dt className="tw:text-muted">Client</dt><dd><Link className="tw:text-accent tw:hover:underline" to={`/host/${alert.clientId}`}><Mono>{alert.clientId}</Mono></Link></dd></>}
            {detailEntries(alert).map(([k, v]) => (
              <Detail key={k} label={k} value={fmtValue(v)} />
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

// Values come from endpoints and may be attacker controlled, so they are
// only ever rendered as plain text.
function Detail({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="tw:text-muted tw:truncate">{label}</dt>
      <dd className="tw:min-w-0"><pre className="tw:whitespace-pre-wrap tw:break-all tw:font-mono tw:text-[11px] tw:max-h-48 tw:overflow-auto">{value}</pre></dd>
    </>
  );
}
