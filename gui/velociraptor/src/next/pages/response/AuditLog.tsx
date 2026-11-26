// Response audit trail, read from the server's own audit log
// (Server.Audit.Logs). The server records who did what; the reason comes
// from the request's user_data.
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ScrollText } from 'lucide-react';
import { useEventTable } from '../../lib/queries';
import { fmtTime, timeAgo, toDate } from '../../lib/format';
import type { Row } from '../../lib/table';
import { Badge, Card, CardHeader, EmptyState, Mono, Segmented, Skeleton, Tooltip } from '../../ui/primitives';
import { ACTIONS } from './actions';
import { decodeUserData } from './approval';

const RESPONSE_ARTIFACTS = new Set(ACTIONS.flatMap(a => a.artifacts));
const OPS = new Set(['CreateHunt', 'ScheduleFlow', 'ModifyHunt']);
const WINDOW = 30 * 24 * 3600;

interface Spec { artifact?: string; parameters?: { env?: { key: string; value: string }[] } }
interface Req { artifacts?: string[]; specs?: Spec[]; user_data?: string; client_id?: string; hunt_description?: string; start_request?: Req; state?: string | number; tags?: string[] }

interface AuditRow {
  key: string;
  time: Date | null;
  principal: string;
  operation: string;
  target: { kind: 'hunt' | 'client'; id: string } | null;
  artifacts: string[];
  live: boolean | null;
  reason: string;
  note: string;
}

function toRow(r: Row, i: number): AuditRow | null {
  const op = String(r.operation ?? '');
  if (!OPS.has(op)) return null;
  const details = (r.details ?? {}) as { hunt_id?: string; client?: string; details?: Req };
  const req = details.details ?? {};
  const inner = req.start_request ?? req;
  const artifacts = inner.artifacts ?? [];
  const isResponse = artifacts.some(a => RESPONSE_ARTIFACTS.has(a));
  if (op !== 'ModifyHunt' && !isResponse) return null;
  if (op === 'ModifyHunt' && !req.state && !req.tags?.some(t => t.startsWith('approval:'))) return null;
  const env = (inner.specs ?? []).flatMap(s => s.parameters?.env ?? []);
  const arm = env.find(e => e.key === 'ReallyDoIt');
  const ud = decodeUserData(inner.user_data);
  const note = op === 'ModifyHunt'
    ? [req.state ? `state → ${req.state}` : '', ...(req.tags ?? []).filter(t => t.startsWith('approval:') && t !== 'approval:pending')].filter(Boolean).join(' · ')
    : req.hunt_description ?? '';
  return {
    key: `${String(r._ts)}-${i}`,
    time: toDate((r._ts ?? r.timestamp) as number),
    principal: String(r.principal ?? ''),
    operation: op,
    target: details.hunt_id ? { kind: 'hunt', id: details.hunt_id } : details.client ? { kind: 'client', id: details.client } : null,
    artifacts,
    // Actions without a dry-run switch (quarantine, sinkhole) are always live.
    live: arm ? arm.value === 'Y' : isResponse ? true : null,
    reason: ud?.reason ?? '',
    note,
  };
}

export function AuditLog() {
  const [range] = useState(() => {
    const now = Math.floor(Date.now() / 1000);
    return { start: now - WINDOW, end: now + 24 * 3600 };
  });
  const [scope, setScope] = useState<'actions' | 'all'>('actions');
  const q = useEventTable('server', 'Server.Audit.Logs', range, false, true);
  // One malformed row must not blank the whole table.
  const safeRow = (r: Row, i: number): AuditRow | null => {
    try { return toRow(r, i); } catch { return null; }
  };
  const rows = useMemo(() => (q.data?.pages ?? []).flatMap(p => p.rows)
    .map(safeRow).filter((r): r is AuditRow => !!r)
    .filter(r => scope === 'all' || r.operation !== 'ModifyHunt')
    .sort((a, b) => (b.time?.getTime() ?? 0) - (a.time?.getTime() ?? 0)), [q.data, scope]);

  return (
    <Card>
      <CardHeader icon={<ScrollText className="tw:size-4" />} title="Audit log"
        subtitle="Response actions from the server audit log, last 30 days. The user is recorded by the server."
        actions={<Segmented value={scope} onChange={v => setScope(v as 'actions' | 'all')}
          options={[{ value: 'actions', label: 'Actions' }, { value: 'all', label: 'With hunt state changes' }]} />} />
      {q.isLoading ? <div className="tw:p-4"><Skeleton className="tw:h-24" /></div> : rows.length === 0 ? (
        <EmptyState icon={<ScrollText />} title="No response actions recorded">Live and dry-run response actions appear here.</EmptyState>
      ) : (
        <div className="tw:overflow-x-auto">
          <table className="tw:w-full tw:text-xs">
            <thead className="tw:text-left tw:text-muted tw:border-b tw:border-line">
              <tr>{['When', 'User', 'Operation', 'Target', 'Action', 'Mode', 'Reason / detail'].map(h => <th key={h} className="tw:px-3 tw:py-2 tw:font-medium">{h}</th>)}</tr>
            </thead>
            <tbody className="tw:divide-y tw:divide-line">
              {rows.map(r => (
                <tr key={r.key} className="tw:align-top">
                  <td className="tw:px-3 tw:py-2 tw:whitespace-nowrap"><Tooltip content={fmtTime(r.time)}><span>{timeAgo(r.time)}</span></Tooltip></td>
                  <td className="tw:px-3 tw:py-2 tw:font-medium">{r.principal}</td>
                  <td className="tw:px-3 tw:py-2">{r.operation}</td>
                  <td className="tw:px-3 tw:py-2">
                    {r.target && <Link className="tw:text-accent tw:hover:underline" to={r.target.kind === 'hunt' ? `/hunts/${r.target.id}` : `/host/${r.target.id}`}><Mono className="tw:text-[11px]">{r.target.id}</Mono></Link>}
                  </td>
                  <td className="tw:px-3 tw:py-2 tw:font-mono tw:text-[11px]">{r.artifacts.join(', ')}</td>
                  <td className="tw:px-3 tw:py-2">{r.live === null ? '' : r.live ? <Badge tone="bad">Live</Badge> : <Badge tone="info">Dry run</Badge>}</td>
                  <td className="tw:px-3 tw:py-2 tw:whitespace-pre-wrap tw:break-words tw:max-w-md">{r.reason || r.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
