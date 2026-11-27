// Click-to-pivot: any value in a results table can be hunted for, added
// to a case, looked up or used as a filter, without copy and paste.
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Briefcase, Copy, ExternalLink, Filter, Laptop, Monitor, Radar, Rows3, ScanSearch,
} from 'lucide-react';
import type { Row } from '../lib/table';
import { prefillIocSweep, rapidHuntUrl } from '../lib/prefill';
import { classify } from '../pages/ioc/parse';
import { cleanIndicator, pivotKind, RAPID_KIND_LABEL } from '../pages/dashboard/rapid/model';
import { AddToCaseDialog } from '../pages/cases/AddToCaseDialog';
import { cn } from './primitives';

export interface PivotTarget {
  value: unknown;
  column: string;
  row: Row;
  x: number;
  y: number;
}

/** Where a row came from, so "Add row to case" can link back to it. */
export interface RowSource {
  ref: string;        // hunt id (H.) or flow id (F.)
  clientId?: string;
  label: string;      // e.g. "Hunt H.123 · Windows.System.Pslist"
}

const HOST_COL = /^(hostname|fqdn|host|computer|computername|workstationname)$/i;

const VT_KINDS = new Set(['sha256', 'sha1', 'md5', 'ip', 'domain']);

function Item({ icon, children, onSelect }: { icon: React.ReactNode; children: React.ReactNode; onSelect: () => void }) {
  return (
    <button type="button" role="menuitem" onClick={onSelect}
      className="tw:flex tw:w-full tw:items-center tw:gap-2 tw:h-7 tw:px-2 tw:rounded-md tw:text-[13px] tw:text-left tw:hover:bg-hover tw:focus:bg-hover tw:outline-none tw:[&>svg]:size-3.5 tw:[&>svg]:text-faint tw:[&>svg]:shrink-0">
      {icon}<span className="tw:truncate">{children}</span>
    </button>
  );
}

export function PivotMenu({ target, onClose, onFilter, source }: {
  target: PivotTarget;
  onClose: () => void;
  onFilter?: (v: string) => void;
  source?: RowSource;
}) {
  const history = useHistory();
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: target.x, y: target.y });
  const [caseItem, setCaseItem] = useState<'indicator' | 'row' | null>(null);

  const text = typeof target.value === 'object' && target.value !== null
    ? JSON.stringify(target.value) : String(target.value ?? '');
  const value = cleanIndicator(text);
  const kind = pivotKind(target.column, text);
  const iocType = kind ? classify(value) : null;
  const clientId = String(target.row.ClientId ?? source?.clientId ?? '');
  const isClientId = /^C\.[0-9a-f]{16}$/.test(value);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos({
      x: Math.max(8, Math.min(target.x, window.innerWidth - r.width - 8)),
      y: Math.max(8, Math.min(target.y, window.innerHeight - r.height - 8)),
    });
  }, [target.x, target.y]);

  useEffect(() => {
    if (caseItem) return undefined;
    const onDown = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) onClose(); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('mousedown', onDown); window.removeEventListener('keydown', onKey); };
  }, [onClose, caseItem]);

  const go = (path: string) => { onClose(); history.push(path); };
  const short = value.length > 48 ? `${value.slice(0, 45)}…` : value;

  if (caseItem === 'indicator' && kind) {
    return <AddToCaseDialog onClose={onClose} suggestedTitle={`Investigation: ${short}`}
      item={{ kind: 'indicator', ref: value, label: `${RAPID_KIND_LABEL[kind]}: ${value}`, clientId: clientId || undefined }} />;
  }
  if (caseItem === 'row') {
    return <AddToCaseDialog onClose={onClose} suggestedTitle={`Investigation: ${short}`}
      item={{
        kind: 'row', ref: source?.ref ?? '', clientId: clientId || undefined,
        label: `${source?.label ?? 'Result row'}${target.row.Fqdn ? ` on ${String(target.row.Fqdn)}` : ''}: ${target.column} = ${short}`,
        data: target.row,
      }} />;
  }

  return (
    <div ref={ref} role="menu" style={{ left: pos.x, top: pos.y }}
      className={cn('rx tw:fixed tw:z-[1800] tw:w-72 tw:rounded-lg tw:border tw:border-line tw:bg-raised tw:p-1 rx-shadow-lg tw:animate-fade-in')}
      onClick={e => e.stopPropagation()}>
      <div className="tw:px-2 tw:py-1 tw:text-2xs tw:text-faint tw:truncate">
        {target.column}: <span className="tw:font-mono">{short || '(empty)'}</span>
      </div>
      {value && onFilter && <Item icon={<Filter />} onSelect={() => { onFilter(value); onClose(); }}>Filter rows to this value</Item>}
      {value && <Item icon={<Copy />} onSelect={() => {
        void navigator.clipboard?.writeText(text).then(() => toast.success('Copied'), () => toast.error('Could not copy'));
        onClose();
      }}>Copy</Item>}
      {kind && <>
        <div className="tw:my-1 tw:h-px tw:bg-line" />
        <Item icon={<Radar />} onSelect={() => go(rapidHuntUrl(value))}>Rapid hunt this {RAPID_KIND_LABEL[kind].toLowerCase()}</Item>
        {iocType && <Item icon={<ScanSearch />} onSelect={() => { prefillIocSweep(value); go('/ioc'); }}>IOC sweep for it</Item>}
        {iocType && VT_KINDS.has(iocType) && (
          <Item icon={<ExternalLink />} onSelect={() => {
            window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`, '_blank', 'noopener,noreferrer');
            onClose();
          }}>Look up on VirusTotal</Item>
        )}
        <Item icon={<Briefcase />} onSelect={() => setCaseItem('indicator')}>Add indicator to a case…</Item>
      </>}
      {(HOST_COL.test(target.column) || iocType === 'ip') && value && (
        <Item icon={<Monitor />} onSelect={() => go(`/search/${encodeURIComponent(iocType === 'ip' ? `ip:${value}` : value)}`)}>Find this client</Item>
      )}
      {isClientId && <Item icon={<Laptop />} onSelect={() => go(`/host/${value}`)}>Open host</Item>}
      {source && <>
        <div className="tw:my-1 tw:h-px tw:bg-line" />
        <Item icon={<Rows3 />} onSelect={() => setCaseItem('row')}>Add this row to a case…</Item>
      </>}
    </div>
  );
}
