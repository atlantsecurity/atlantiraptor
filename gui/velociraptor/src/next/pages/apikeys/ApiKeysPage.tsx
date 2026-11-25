// SIEM/SOAR API keys: create, list and revoke keys, with the API
// reference and integration examples. Keys are scoped by role and
// enforced on the server like console users.
import { useState } from 'react';
import { toast } from 'sonner';
import { BookOpen, KeyRound, Plug, Plus, Trash2 } from 'lucide-react';
import { apiBaseUrl, useApiKeys, useCreateApiKey, useRevokeApiKey, type ApiKey, type CreatedKey } from '../../lib/apikeys';
import { Badge, Button, Card, CardHeader, ConfirmDialog, CopyButton, Dialog, EmptyState, Field, IconButton, Input, Mono, Select, Skeleton, Tabs, cn } from '../../ui/primitives';
import { ROLE_INFO, sortRoles } from '../users/UsersPage';

// What each role lets an API key do through this REST API.
const KEY_ROLE_HELP: Record<string, string> = {
  api: 'Only lets a program use the gRPC API port. Adds nothing for this REST API.',
  reader: 'Read alerts, hosts, collections and their results, hunts, cases and artifacts. Nothing runs on endpoints.',
  analyst: 'Everything Reader can, plus server-side queries over the collected data.',
  investigator: 'Everything Analyst can, plus collections on hosts and hunts with read-only artifacts.',
  hunter: 'Collections, hunts, quick triage and IOC sweeps. Response actions are refused.',
  responder: 'Everything Hunter can, plus response actions: quarantine, kill, delete, disable accounts. Live actions need a reason and follow your approval policy.',
};
import { EXAMPLES } from './examples';
import { ConnectSiemDialog } from './ConnectSiem';

const fmt = (t?: number) => (t ? new Date(t * 1000).toLocaleString() : '—');

export default function ApiKeysPage() {
  const { data, isLoading, error } = useApiKeys();
  const [creating, setCreating] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [created, setCreated] = useState<CreatedKey | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const revoke = useRevokeApiKey();

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><KeyRound className="tw:size-5 tw:text-accent" />API keys</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Connect a SIEM or SOAR. Each key has roles and is checked like a console user with those roles,
              rate limited, and every action it takes is in the audit log.
            </p>
          </div>
          <Button variant="secondary" icon={<Plus className="tw:size-3.5" />} onClick={() => setCreating(true)}>New API key</Button>
          <Button variant="primary" icon={<Plug className="tw:size-3.5" />} onClick={() => setConnecting(true)}>Connect a SIEM</Button>
        </div>

        <Card>
          <CardHeader icon={<KeyRound className="tw:size-4" />} title="Keys in this org" />
          {isLoading && <div className="tw:p-4"><Skeleton className="tw:h-20" /></div>}
          {error && <EmptyState icon={<KeyRound />} title="API keys are not available">{(error as Error).message}</EmptyState>}
          {data && data.keys.length === 0 && (
            <EmptyState icon={<KeyRound />} title="No API keys yet">
              For example “Splunk alerts” with Reader, or “SOAR response” with Responder.
            </EmptyState>
          )}
          {data && data.keys.length > 0 && (
            <div className="tw:overflow-x-auto">
              <table className="tw:w-full tw:text-[13px]">
                <thead className="tw:text-xs tw:text-muted tw:text-left">
                  <tr>{['Name', 'Key', 'Roles', 'Created', 'Last used', 'Expires', ''].map(h => <th key={h} className="tw:px-4 tw:py-2 tw:font-medium">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {data.keys.map(k => {
                    const expired = !!k.expires && k.expires * 1000 < Date.now();
                    return (
                      <tr key={k.id} className="tw:border-t tw:border-line">
                        <td className="tw:px-4 tw:py-2 tw:font-medium">{k.name}</td>
                        <td className="tw:px-4 tw:py-2"><Mono>atl_{k.id}_{k.hint}…</Mono></td>
                        <td className="tw:px-4 tw:py-2"><div className="tw:flex tw:flex-wrap tw:gap-1">{sortRoles(k.roles).map(r => <Badge key={r}>{ROLE_INFO[r]?.label ?? r}</Badge>)}</div></td>
                        <td className="tw:px-4 tw:py-2 tw:text-xs">{fmt(k.created)}<div className="tw:text-muted">by {k.created_by}</div></td>
                        <td className="tw:px-4 tw:py-2 tw:text-xs">{fmt(k.last_used)}</td>
                        <td className={cn('tw:px-4 tw:py-2 tw:text-xs', expired && 'tw:text-bad')}>{k.expires ? fmt(k.expires) : 'Never'}{expired && ' (expired)'}</td>
                        <td className="tw:px-4 tw:py-2 tw:text-right">
                          <IconButton size="xs" variant="ghost" label="Revoke key" icon={<Trash2 className="tw:size-3.5" />} onClick={() => setRevoking(k)} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <ApiDocs />
      </div>

      <ConnectSiemDialog open={connecting} onOpenChange={setConnecting} connection={data?.connection} />
      <CreateDialog open={creating} onOpenChange={setCreating} roles={data?.roles ?? []}
        onCreated={k => { setCreating(false); setCreated(k); }} />
      <Dialog open={!!created} onOpenChange={v => !v && setCreated(null)} title="Copy your API key now"
        description="This is the only time the key is shown. Store it in your SIEM or SOAR's secret store."
        footer={<Button variant="primary" onClick={() => setCreated(null)}>I have copied it</Button>}>
        {created && (
          <div className="tw:flex tw:items-center tw:gap-2 tw:rounded-md tw:border tw:border-line tw:bg-sunken tw:p-2">
            <Mono className="tw:break-all tw:flex-1">{created.token}</Mono>
            <CopyButton text={created.token} />
          </div>
        )}
      </Dialog>
      <ConfirmDialog open={!!revoking} onOpenChange={v => !v && setRevoking(null)} danger
        title={`Revoke “${revoking?.name}”?`} confirmLabel="Revoke key" loading={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking.id, {
          onSuccess: () => { toast.success('Key revoked'); setRevoking(null); },
          onError: e => toast.error((e as Error).message),
        })}>
        Anything using this key stops working immediately. Hunts and collections it started keep running.
      </ConfirmDialog>
    </div>
  );
}

function CreateDialog({ open, onOpenChange, roles, onCreated }: {
  open: boolean; onOpenChange: (v: boolean) => void; roles: string[]; onCreated: (k: CreatedKey) => void;
}) {
  const create = useCreateApiKey();
  const [name, setName] = useState('');
  const [picked, setPicked] = useState<string[]>(['reader']);
  const [ttl, setTtl] = useState('365');
  const submit = () => create.mutate({ name: name.trim(), roles: picked, ttl_days: Number(ttl) }, {
    onSuccess: k => { setName(''); setPicked(['reader']); onCreated(k); },
    onError: e => toast.error((e as Error).message),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="New API key"
      footer={<>
        <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button variant="primary" loading={create.isPending} disabled={!name.trim() || picked.length === 0} onClick={submit}>Create key</Button>
      </>}>
      <div className="tw:space-y-3">
        <Field label="Name" required><Input value={name} onChange={e => setName(e.target.value)} placeholder="Splunk alerts" /></Field>
        <Field label="Roles" hint="Listed from least to most permission. A key gets everything its roles allow, checked by the server on every call.">
          <div className="tw:rounded-md tw:border tw:border-line tw:divide-y tw:divide-line">
            {sortRoles(roles).map(r => {
              const on = picked.includes(r);
              return (
                <label key={r} className={cn('tw:flex tw:items-start tw:gap-2.5 tw:px-3 tw:py-2 tw:cursor-pointer', on ? 'tw:bg-accent-soft' : 'tw:hover:bg-hover')}>
                  <input type="checkbox" className="tw:mt-0.5" checked={on}
                    onChange={() => setPicked(p => (on ? p.filter(x => x !== r) : [...p, r]))} />
                  <span className="tw:min-w-0">
                    <span className="tw:block tw:text-[13px] tw:font-medium">{ROLE_INFO[r]?.label ?? r}{ROLE_INFO[r]?.danger ? ' ⚠' : ''}</span>
                    <span className="tw:block tw:text-xs tw:text-muted">{KEY_ROLE_HELP[r] ?? ROLE_INFO[r]?.blurb}</span>
                  </span>
                </label>
              );
            })}
          </div>
        </Field>
        <Field label="Expires">
          <Select value={ttl} onChange={e => setTtl(e.target.value)}>
            <option value="30">In 30 days</option>
            <option value="90">In 90 days</option>
            <option value="365">In a year</option>
            <option value="0">Never</option>
          </Select>
        </Field>
      </div>
    </Dialog>
  );
}

const ENDPOINTS: [string, string, string][] = [
  ['GET', '/actions', 'Response actions and quick-triage collections, with their parameters'],
  ['POST', '/actions/{id}/run', 'Run an action on a host, labels, an OS or all hosts (dry run by default)'],
  ['GET', '/alerts?since=', 'Detection alerts after a cursor; poll with next_since'],
  ['GET', '/clients?q=', 'Endpoints, using the console search syntax'],
  ['GET', '/clients/{id}/flows/{flow}', 'Collection status; /results?artifact= for rows'],
  ['POST', '/collections', 'Collect read-only artifacts from one host (response artifacts go through /actions)'],
  ['GET/POST', '/hunts', 'List or start hunts; /hunts/{id}/results?artifact='],
  ['POST', '/ioc-sweeps', 'Sweep hosts for hashes, IPs, domains, paths, file names'],
  ['GET', '/cases', 'Investigation cases'],
  ['GET', '/artifacts/{name}', 'Artifact definitions, parameters and YAML'],
  ['POST', '/rapid-hunts', 'Rapid hunt: which machines visited a domain, URL or IP'],
  ['GET', '/rapid-hunts/{id}', 'Rapid hunt results per machine, live as machines answer'],
  ['GET', '/approvals', 'Live response actions waiting for a second person'],
  ['POST', '/approvals/{id}/approve', 'Approve or reject (…/reject); never by the requester'],
  ['POST', '/hunts/{id}/stop', 'Stop a hunt (…/start for paused, non-pending hunts)'],
  ['GET', '/clients/{id}', 'One endpoint: OS, agent, labels, IP, metadata'],
  ['POST', '/clients/{id}/labels', 'Add or remove labels'],
  ['GET', '/clients/{id}/flows/{flow}/uploads', 'Uploaded files; …/uploads/{n} downloads one'],
  ['POST', '/clients/{id}/flows/{flow}/cancel', 'Cancel a running collection'],
  ['GET', '/stats', 'Clients total and online, running hunts, pending approvals'],
  ['POST', '/query', 'VQL over collected data (analyst keys only)'],
];

function ApiDocs() {
  const [tab, setTab] = useState(EXAMPLES[0].id);
  const base = apiBaseUrl();
  const ex = EXAMPLES.find(e => e.id === tab) ?? EXAMPLES[0];
  const code = ex.code.split('{BASE}').join(base);
  return (
    <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] tw:gap-4 tw:items-start">
      <Card>
        <CardHeader icon={<BookOpen className="tw:size-4" />} title="API reference"
          actions={<a className="tw:text-xs tw:text-accent tw:hover:underline" href={`${base}/openapi.yaml`} target="_blank" rel="noreferrer">OpenAPI spec</a>} />
        <div className="tw:px-4 tw:pb-4 tw:space-y-3 tw:text-[13px]">
          <div className="tw:flex tw:items-center tw:gap-2">
            <span className="tw:text-xs tw:text-muted">Base URL</span><Mono className="tw:break-all">{base}</Mono><CopyButton text={base} />
          </div>
          <p className="tw:text-xs tw:text-muted">Send <Mono>Authorization: Bearer atl_…</Mono> on every request. Responses are JSON with a <Mono>data</Mono> field. Errors return <Mono>error</Mono>; 429 means slow down.</p>
          <table className="tw:w-full tw:text-xs">
            <tbody>
              {ENDPOINTS.map(([m, p, d]) => (
                <tr key={p} className="tw:border-t tw:border-line tw:align-top">
                  <td className="tw:py-1.5 tw:pr-2"><Badge>{m}</Badge></td>
                  <td className="tw:py-1.5 tw:pr-2"><Mono>{p}</Mono></td>
                  <td className="tw:py-1.5 tw:text-muted">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="tw:text-xs tw:text-muted">
            Live response actions need a <Mono>reason</Mono>. When two-person approval is on (Response page), they wait as paused hunts
            until someone approves them in the console.
          </p>
        </div>
      </Card>
      <Card>
        <Tabs value={tab} onValueChange={setTab} tabs={EXAMPLES.map(e => ({ value: e.id, label: e.title }))} />
        <div className="tw:p-4 tw:space-y-2">
          <div className="tw:flex tw:items-start tw:gap-2">
            <p className="tw:text-xs tw:text-muted tw:flex-1">{ex.blurb}</p>
            <CopyButton text={code} />
          </div>
          <pre className="tw:rounded-md tw:bg-sunken tw:border tw:border-line tw:p-3 tw:text-[12px] tw:overflow-x-auto tw:leading-relaxed"><code>{code}</code></pre>
        </div>
      </Card>
    </div>
  );
}
