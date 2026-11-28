// Server settings > Audit log: browse, filter and export the server's
// tamper-evident audit log, check its integrity, and choose where it is
// kept and whether it is forwarded to syslog.
import React, { useState } from 'react';
import { toast } from 'sonner';
import {
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Download, FolderLock, Radio, Save, ScrollText, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import {
  detailsSummary, downloadAudit, useAuditAction, useAuditEntries, useAuditStatus,
  type AuditEntry, type AuditFilter, type AuditSettings, type AuditStatus,
} from '../../lib/auditlog';
import { fmtBytes, fmtTime, timeAgo } from '../../lib/format';
import {
  Badge, Button, Card, CardHeader, Checkbox, CopyButton, EmptyState, Field, Input, Menu, MenuContent, MenuItem, MenuTrigger,
  Mono, SearchInput, Select, Skeleton, Switch, cn,
} from '../../ui/primitives';

export default function AuditPage() {
  const { data, isLoading, error } = useAuditStatus();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<ScrollText />} title="The audit log is not available">{(error as Error)?.message}</EmptyState>;
  }
  return <AuditView status={data} />;
}

function AuditView({ status }: { status: AuditStatus }) {
  const [filter, setFilter] = useState<AuditFilter>({});
  const action = useAuditAction();

  const exportAs = (format: 'jsonl' | 'csv') =>
    downloadAudit(filter, format).catch(e => toast.error((e as Error).message));

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1 tw:min-w-60">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><ScrollText className="tw:size-5 tw:text-accent" />Audit log</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Every sign-in, response action, hunt, collection and settings change, kept on this server's disk outside the datastore.
              Each entry is chained to the one before it and the chain is signed regularly, so a changed or removed entry shows up below.
            </p>
          </div>
          <Button icon={<ShieldCheck className="tw:size-3.5" />} loading={action.isPending && action.variables?.action === 'verify'}
            disabled={!status.enabled} onClick={() => action.mutate({ action: 'verify' }, {
              onSuccess: d => (d.last_verify?.ok ? toast.success('The audit log is intact') : toast.error('The audit log failed the check')),
              onError: e => toast.error((e as Error).message),
            })}>Check integrity</Button>
          <Menu>
            <MenuTrigger asChild>
              <Button icon={<Download className="tw:size-3.5" />} disabled={!status.enabled}>Export <ChevronDown className="tw:size-3" /></Button>
            </MenuTrigger>
            <MenuContent>
              <MenuItem onSelect={() => exportAs('jsonl')}>JSON lines (verifiable)</MenuItem>
              <MenuItem onSelect={() => exportAs('csv')}>CSV (spreadsheet)</MenuItem>
            </MenuContent>
          </Menu>
        </div>

        {!status.enabled && (
          <Card className="tw:border-bad">
            <div className="tw:flex tw:items-start tw:gap-3 tw:px-4 tw:py-3 tw:text-[13px]">
              <AlertTriangle className="tw:size-4 tw:text-bad tw:mt-0.5 tw:shrink-0" />
              <div>
                <div className="tw:font-medium">The audit log is not being written.</div>
                <div className="tw:text-muted tw:text-xs tw:mt-0.5">{status.reason || 'Unknown reason.'} Events are held in memory until it opens.</div>
              </div>
            </div>
          </Card>
        )}

        <Integrity status={status} />
        <Entries filter={filter} setFilter={setFilter} enabled={status.enabled} />
        <SettingsCard key={status.settings.updated ?? 0} status={status} />
      </div>
    </div>
  );
}

function Integrity({ status }: { status: AuditStatus }) {
  const v = status.last_verify;
  const errors = v?.problems.filter(p => p.severity === 'error') ?? [];
  const warnings = v?.problems.filter(p => p.severity === 'warning') ?? [];
  return (
    <Card>
      <CardHeader icon={v && !v.ok ? <ShieldAlert className="tw:size-4 tw:text-bad" /> : <ShieldCheck className="tw:size-4" />}
        title="Integrity"
        subtitle={v ? `Checked ${timeAgo(new Date(v.checked * 1000))} in ${v.duration_ms} ms. The server checks every 6 hours and after each start.` : 'Not checked yet.'}
        actions={status.verifying ? <Badge tone="neutral">checking…</Badge>
          : !v ? <Badge tone="neutral">not checked</Badge>
          : v.ok ? <Badge tone="ok" dot>intact</Badge>
          : <Badge tone="bad" dot>{v.errors} problem{v.errors === 1 ? '' : 's'}</Badge>} />
      <div className="tw:grid tw:grid-cols-2 tw:md:grid-cols-4 tw:gap-x-6 tw:gap-y-3 tw:px-4 tw:py-3 tw:text-[13px]">
        <Fact label="Entries">{status.head.seq.toLocaleString()}{status.head.time && <span className="tw:text-muted"> · last {timeAgo(new Date(status.head.time))}</span>}</Fact>
        <Fact label="Signed checkpoints">
          {v ? <>{v.checkpoints.toLocaleString()}{v.last_checkpoint_time && <span className="tw:text-muted"> · last {timeAgo(new Date(v.last_checkpoint_time))}</span>}</> : '–'}
        </Fact>
        <Fact label="Files on disk">{status.files} · {fmtBytes(status.bytes)}</Fact>
        <Fact label="Signing key"><Mono>{status.key_id || '–'}</Mono>{status.public_key && <CopyButton text={status.public_key} />}</Fact>
      </div>
      {(errors.length > 0 || warnings.length > 0) && (
        <ul className="tw:border-t tw:border-line tw:px-4 tw:py-3 tw:space-y-1.5 tw:text-xs">
          {[...errors, ...warnings].map((p, i) => (
            <li key={i} className="tw:flex tw:items-start tw:gap-2">
              {p.severity === 'error'
                ? <AlertTriangle className="tw:size-3.5 tw:text-bad tw:mt-px tw:shrink-0" />
                : <AlertTriangle className="tw:size-3.5 tw:text-warn tw:mt-px tw:shrink-0" />}
              <span>{p.message}{p.file && <span className="tw:text-faint"> ({p.file})</span>}</span>
            </li>
          ))}
        </ul>
      )}
      {status.write_errors > 0 && (
        <div className="tw:border-t tw:border-line tw:px-4 tw:py-2 tw:text-xs tw:text-bad">
          {status.write_errors} entr{status.write_errors === 1 ? 'y' : 'ies'} could not be written. Last error: {status.last_write_error}
        </div>
      )}
    </Card>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="tw:min-w-0">
      <div className="tw:text-2xs tw:uppercase tw:tracking-wider tw:text-faint tw:font-semibold">{label}</div>
      <div className="tw:mt-0.5 tw:truncate">{children}</div>
    </div>
  );
}

function Entries({ filter, setFilter, enabled }: {
  filter: AuditFilter; setFilter: (f: AuditFilter) => void; enabled: boolean;
}) {
  const q = useAuditEntries(filter, enabled);
  const rows = q.data?.pages.flatMap(p => p.entries) ?? [];
  const [open, setOpen] = useState<number | null>(null);
  const set = (k: keyof AuditFilter) => (v: string | boolean) => setFilter({ ...filter, [k]: v });

  return (
    <Card>
      <CardHeader icon={<ScrollText className="tw:size-4" />} title="Entries" subtitle="Newest first. Filters also apply to Export." />
      <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-2 tw:px-4 tw:py-3 tw:border-b tw:border-line">
        <SearchInput className="tw:w-full tw:sm:w-64" value={filter.q ?? ''} onChange={set('q')} placeholder="Search anywhere in an entry" />
        <Input className="tw:w-full tw:sm:w-36" value={filter.principal ?? ''} onChange={e => set('principal')(e.target.value)} placeholder="User" aria-label="User" />
        <Input className="tw:w-full tw:sm:w-40" value={filter.operation ?? ''} onChange={e => set('operation')(e.target.value)} placeholder="Action" aria-label="Action" />
        <Input className="tw:w-full tw:sm:w-28" value={filter.org ?? ''} onChange={e => set('org')(e.target.value)} placeholder="Org ID" aria-label="Org ID" />
        <label className="tw:flex tw:items-center tw:gap-1 tw:text-xs tw:text-muted">From
          <Input type="datetime-local" className="tw:w-48" value={filter.from ?? ''} onChange={e => set('from')(e.target.value)} />
        </label>
        <label className="tw:flex tw:items-center tw:gap-1 tw:text-xs tw:text-muted">To
          <Input type="datetime-local" className="tw:w-48" value={filter.to ?? ''} onChange={e => set('to')(e.target.value)} />
        </label>
        <label className="tw:flex tw:items-center tw:gap-1.5 tw:text-xs tw:text-muted tw:h-8">
          <Checkbox checked={!!filter.checkpoints} onChange={set('checkpoints')} label="Show checkpoints" />Show checkpoints
        </label>
      </div>

      {q.isLoading ? <div className="tw:p-4"><Skeleton className="tw:h-32" /></div>
        : q.error ? <div className="tw:p-4 tw:text-xs tw:text-bad">{(q.error as Error).message}</div>
        : rows.length === 0 ? <div className="tw:p-6 tw:text-center tw:text-xs tw:text-muted">No entries match.</div>
        : (
          <div className="tw:overflow-x-auto">
            <table className="tw:w-full tw:text-[13px]">
              <thead>
                <tr className="tw:text-left tw:text-2xs tw:uppercase tw:tracking-wider tw:text-faint tw:border-b tw:border-line">
                  <th className="tw:w-6" />
                  <th className="tw:px-2 tw:py-2 tw:font-semibold tw:whitespace-nowrap">Time</th>
                  <th className="tw:px-2 tw:py-2 tw:font-semibold">User</th>
                  <th className="tw:px-2 tw:py-2 tw:font-semibold">Action</th>
                  <th className="tw:px-2 tw:py-2 tw:font-semibold tw:hidden tw:md:table-cell">Org</th>
                  <th className="tw:px-2 tw:py-2 tw:font-semibold tw:hidden tw:lg:table-cell">Details</th>
                  <th className="tw:px-2 tw:py-2 tw:font-semibold tw:text-right">#</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(e => <EntryRow key={e.seq} e={e} open={open === e.seq} onToggle={() => setOpen(open === e.seq ? null : e.seq)} />)}
              </tbody>
            </table>
          </div>
        )}
      {q.hasNextPage && (
        <div className="tw:p-3 tw:border-t tw:border-line tw:text-center">
          <Button size="sm" loading={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>Load older entries</Button>
        </div>
      )}
    </Card>
  );
}

function EntryRow({ e, open, onToggle }: { e: AuditEntry; open: boolean; onToggle: () => void }) {
  const bookkeeping = e.type !== 'event';
  return (
    <>
      <tr onClick={onToggle}
        className={cn('tw:border-b tw:border-line tw:cursor-pointer tw:hover:bg-hover tw:align-top', bookkeeping && 'tw:text-muted')}>
        <td className="tw:pl-2 tw:py-1.5 tw:text-faint">{open ? <ChevronDown className="tw:size-3.5" /> : <ChevronRight className="tw:size-3.5" />}</td>
        <td className="tw:px-2 tw:py-1.5 tw:whitespace-nowrap">{fmtTime(new Date(e.time))}</td>
        <td className="tw:px-2 tw:py-1.5 tw:whitespace-nowrap">{e.principal}</td>
        <td className="tw:px-2 tw:py-1.5">
          <span className="tw:inline-flex tw:items-center tw:gap-1.5">
            {e.type === 'checkpoint' && <CheckCircle2 className="tw:size-3.5 tw:text-ok" />}
            {e.operation}
          </span>
        </td>
        <td className="tw:px-2 tw:py-1.5 tw:hidden tw:md:table-cell"><Mono>{e.org_id}</Mono></td>
        <td className="tw:px-2 tw:py-1.5 tw:hidden tw:lg:table-cell tw:text-xs tw:text-muted tw:max-w-xl tw:truncate">{detailsSummary(e.details)}</td>
        <td className="tw:px-2 tw:py-1.5 tw:text-right tw:text-faint"><Mono>{e.seq}</Mono></td>
      </tr>
      {open && (
        <tr className="tw:border-b tw:border-line tw:bg-sidebar">
          <td />
          <td colSpan={6} className="tw:px-2 tw:py-3 tw:space-y-2">
            <pre className="tw:text-xs tw:font-mono tw:whitespace-pre-wrap tw:break-all tw:max-h-80 tw:overflow-auto">{JSON.stringify(e.details, null, 2)}</pre>
            <div className="tw:text-2xs tw:text-faint tw:font-mono tw:break-all tw:space-y-0.5">
              <div>type {e.type}{e.key_id ? ` · key ${e.key_id}` : ''}{e.sig ? ' · signed' : ''}</div>
              <div>hash {e.hash}</div>
              <div>prev {e.prev || '(start of chain)'}</div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function SettingsCard({ status }: { status: AuditStatus }) {
  const save = useAuditAction();
  const [draft, setDraft] = useState<AuditSettings>({
    directory: status.settings.directory ?? '',
    syslog: { enabled: !!status.settings.syslog?.enabled, server: status.settings.syslog?.server ?? '', protocol: status.settings.syslog?.protocol || 'udp' },
  });
  const submit = () => save.mutate({ action: 'settings', settings: draft }, {
    onSuccess: () => toast.success('Audit log settings saved'),
    onError: e => toast.error((e as Error).message),
  });
  const setSyslog = (p: Partial<AuditSettings['syslog']>) => setDraft({ ...draft, syslog: { ...draft.syslog, ...p } });

  return (
    <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
      <Card>
        <CardHeader icon={<FolderLock className="tw:size-4" />} title="Where it is kept"
          subtitle={<>Now: <Mono>{status.directory || 'nowhere'}</Mono></>} />
        <div className="tw:px-4 tw:py-3 tw:space-y-3">
          {status.env_override ? (
            <p className="tw:text-xs tw:text-muted">The folder is set with the <Mono>ATLANTIRAPTOR_AUDIT_DIR</Mono> environment variable on the server and can't be changed here.</p>
          ) : (
            <Field label="Folder" hint={<>Leave empty for the default, <Mono>{status.default_directory || 'none'}</Mono>. A full path outside the datastore. Changing it signs and closes the log in the old folder and continues in the new one.</>}>
              <Input value={draft.directory} onChange={e => setDraft({ ...draft, directory: e.target.value })}
                placeholder={status.default_directory} className="tw:font-mono tw:text-xs" />
            </Field>
          )}
          <p className="tw:text-2xs tw:text-faint">
            Check a copy anywhere with <Mono>Atlantiraptor.exe audit verify --dir &lt;folder&gt; --key {status.public_key ? status.public_key.slice(0, 10) + '…' : '<public key>'}</Mono> (use
            Copy next to the signing key above), or on the server with <Mono>audit verify --config server.config.yaml</Mono>.
          </p>
        </div>
      </Card>

      <Card>
        <CardHeader icon={<Radio className="tw:size-4" />} title="Forward to syslog or a SIEM"
          subtitle="Each entry, exactly as written, the moment it is written."
          actions={<Switch checked={draft.syslog.enabled} onChange={v => setSyslog({ enabled: v })} label={draft.syslog.enabled ? 'On' : 'Off'} />} />
        <div className={cn('tw:px-4 tw:py-3 tw:space-y-3', !draft.syslog.enabled && 'tw:opacity-60')}>
          <div className="tw:flex tw:flex-wrap tw:gap-3">
            <Field label="Server" className="tw:flex-1 tw:min-w-48">
              <Input value={draft.syslog.server} onChange={e => setSyslog({ server: e.target.value })} placeholder="siem.example.com:514" className="tw:font-mono tw:text-xs" />
            </Field>
            <Field label="Protocol" className="tw:w-32">
              <Select value={draft.syslog.protocol} onChange={e => setSyslog({ protocol: e.target.value })}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
                <option value="tls">TCP + TLS</option>
              </Select>
            </Field>
          </div>
          <div className="tw:text-2xs tw:text-faint">
            RFC 5424, facility local0, app name Atlantiraptor, message ID audit. A copy on another system is the best protection against someone with full control of this server.
            {status.forward.active && <> Sent {status.forward.sent.toLocaleString()}{status.forward.dropped > 0 && <span className="tw:text-bad">, dropped {status.forward.dropped}</span>}.</>}
            {status.forward.last_error && <span className="tw:text-bad"> Last error: {status.forward.last_error}</span>}
          </div>
        </div>
      </Card>

      <div className="tw:xl:col-span-2 tw:flex tw:items-center tw:gap-3">
        <Button variant="primary" icon={<Save className="tw:size-3.5" />} loading={save.isPending && save.variables?.action === 'settings'} onClick={submit}>Save settings</Button>
        {status.settings.updated ? <span className="tw:text-2xs tw:text-muted">Last changed by {status.settings.updated_by} {new Date(status.settings.updated * 1000).toLocaleString()}</span> : null}
      </div>
    </div>
  );
}
