// Items linked to a case, with a form to link hunts, collections and
// hosts by ID. Alerts are linked from the dashboard.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { BellRing, Crosshair, Fingerprint, History, Laptop, Link2, Rows3, Trash2 } from 'lucide-react';
import { rapidHuntUrl } from '../../lib/prefill';
import { timeAgo } from '../../lib/format';
import { Button, Card, CardHeader, IconButton, Input, Select } from '../../ui/primitives';
import { useLinkToCase, type NewLink } from './hooks';
import type { CaseLink, CaseRecord, LinkKind } from './model';

const ICON: Record<LinkKind, React.ReactNode> = {
  alert: <BellRing />, hunt: <Crosshair />, flow: <History />, client: <Laptop />,
  indicator: <Fingerprint />, row: <Rows3 />,
};

const HUNT_RE = /^H\.[A-Za-z0-9]+$/;
const FLOW_RE = /^F\.[A-Za-z0-9]+$/;
const CLIENT_RE = /^C\.[0-9a-f]+(-[A-Za-z0-9]+)?$/;

export function linkHref(l: CaseLink): string | null {
  if (l.kind === 'hunt') return `/hunts/${l.ref}`;
  if (l.kind === 'flow' && l.clientId) return `/collected/${l.clientId}/${l.ref}`;
  if (l.kind === 'client') return `/host/${l.ref}`;
  if (l.kind === 'alert' && l.clientId) return `/host/${l.clientId}`;
  if (l.kind === 'indicator') return rapidHuntUrl(l.ref);
  if (l.kind === 'row' && l.clientId && l.ref.startsWith('F.')) return `/collected/${l.clientId}/${l.ref}`;
  if (l.kind === 'row' && l.ref.startsWith('H.')) return `/hunts/${l.ref}/results`;
  return null;
}

export function CaseLinks({ caseId, record, onUnlink }: {
  caseId: string; record: CaseRecord; onUnlink: (linkId: string) => void;
}) {
  return (
    <Card>
      <CardHeader icon={<Link2 className="tw:size-4" />} title="Linked items" subtitle={`${record.links.length} linked`} />
      <div className="tw:divide-y tw:divide-line">
        {record.links.length === 0 && <div className="tw:px-4 tw:py-5 tw:text-xs tw:text-faint">Nothing linked yet.</div>}
        {record.links.map(l => {
          const href = linkHref(l);
          return (
            <div key={l.id} className="tw:group tw:flex tw:items-center tw:gap-2.5 tw:px-4 tw:py-2">
              <span className="tw:flex tw:text-faint tw:[&>svg]:size-4">{ICON[l.kind]}</span>
              <div className="tw:min-w-0 tw:flex-1">
                {href
                  ? <Link to={href} className="tw:block tw:text-[13px] tw:truncate tw:hover:text-accent tw:hover:underline">{l.label}</Link>
                  : <div className="tw:text-[13px] tw:truncate">{l.label}</div>}
                <div className="tw:text-2xs tw:text-faint tw:truncate">{l.kind} · {l.addedBy} · {timeAgo(new Date(l.addedAt))}</div>
                {l.data && (l.kind === 'row' || l.kind === 'alert') && (
                  // Endpoint data: shown as plain text only.
                  <details className="tw:mt-1">
                    <summary className="tw:cursor-pointer tw:text-2xs tw:text-accent">Show data</summary>
                    <pre className="tw:mt-1 tw:max-h-60 tw:overflow-auto tw:whitespace-pre-wrap tw:break-all tw:rounded tw:bg-sunken tw:p-2 tw:font-mono tw:text-[11px]">
                      {JSON.stringify(l.data, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
              <IconButton size="xs" variant="ghost" label="Remove link" icon={<Trash2 className="tw:size-3.5" />}
                className="tw:opacity-0 tw:group-hover:opacity-100" onClick={() => onUnlink(l.id)} />
            </div>
          );
        })}
      </div>
      <LinkForm caseId={caseId} />
    </Card>
  );
}

function LinkForm({ caseId }: { caseId: string }) {
  const link = useLinkToCase();
  const [kind, setKind] = useState<'hunt' | 'flow' | 'client'>('hunt');
  const [ref, setRef] = useState('');
  const [clientId, setClientId] = useState('');
  const [busy, setBusy] = useState(false);

  const valid = kind === 'hunt' ? HUNT_RE.test(ref.trim())
    : kind === 'client' ? CLIENT_RE.test(ref.trim())
    : FLOW_RE.test(ref.trim()) && CLIENT_RE.test(clientId.trim());

  const submit = async () => {
    if (!valid) return;
    const r = ref.trim();
    const item: NewLink = kind === 'flow'
      ? { kind, ref: r, clientId: clientId.trim(), label: `${r} on ${clientId.trim()}` }
      : { kind, ref: r, label: r };
    setBusy(true);
    try {
      await link(caseId, item);
      setRef('');
      setClientId('');
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="tw:border-t tw:border-line tw:p-3 tw:space-y-2">
      <div className="tw:text-xs tw:font-medium">Link an item</div>
      <div className="tw:flex tw:gap-1.5">
        <Select value={kind} onChange={e => setKind(e.target.value as typeof kind)} className="tw:w-28 tw:shrink-0">
          <option value="hunt">Hunt</option>
          <option value="flow">Collection</option>
          <option value="client">Host</option>
        </Select>
        <Input value={ref} onChange={e => setRef(e.target.value)} className="tw:font-mono tw:text-xs"
          placeholder={kind === 'hunt' ? 'H.XXXX' : kind === 'flow' ? 'F.XXXX' : 'C.0123abcd'} />
      </div>
      {kind === 'flow' && (
        <Input value={clientId} onChange={e => setClientId(e.target.value)} className="tw:font-mono tw:text-xs" placeholder="Client ID, e.g. C.0123abcd" />
      )}
      <Button size="sm" variant="secondary" loading={busy} disabled={!valid} onClick={submit} className="tw:w-full">Link</Button>
    </div>
  );
}
