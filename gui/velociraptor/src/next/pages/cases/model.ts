// A case is a shared notebook whose description holds the case record:
// status, severity, owner, linked items and an append-only timeline.
// Notebooks are already stored server-side, shared and access checked,
// and the notebook stays available for VQL analysis of the case.

export const CASE_PREFIX = 'atl-case:v1:';
export const CASE_TAG_PREFIX = 'case:';

export type CaseStatus = 'open' | 'in_progress' | 'closed';
export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low';
export const STATUSES: CaseStatus[] = ['open', 'in_progress', 'closed'];
export const CASE_SEVERITIES: CaseSeverity[] = ['critical', 'high', 'medium', 'low'];
export const STATUS_LABEL: Record<CaseStatus, string> = { open: 'Open', in_progress: 'In progress', closed: 'Closed' };
export const STATUS_TONE: Record<CaseStatus, 'warn' | 'accent' | 'neutral'> = { open: 'warn', in_progress: 'accent', closed: 'neutral' };
export const SEVERITY_TONE: Record<CaseSeverity, 'bad' | 'warn' | 'info'> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info' };

export type LinkKind = 'hunt' | 'flow' | 'client' | 'alert';

export interface CaseLink {
  id: string;
  kind: LinkKind;
  ref: string;          // hunt id, flow id, client id or alert key
  clientId?: string;    // for flows and alerts
  label: string;
  addedBy: string;
  addedAt: number;      // ms since epoch
  data?: Record<string, unknown>; // alert snapshot
}

export type EntryKind = 'created' | 'note' | 'status' | 'severity' | 'owner' | 'link' | 'unlink' | 'summary';

export interface TimelineEntry {
  id: string;
  kind: EntryKind;
  at: number;
  by: string;
  text: string;
}

export interface CaseRecord {
  title: string;
  status: CaseStatus;
  severity: CaseSeverity;
  owner: string;
  summary: string;
  links: CaseLink[];
  timeline: TimelineEntry[];
}

export interface CaseSummary extends CaseRecord {
  id: string;
  creator: string;
  modified: number;
}

export function newId(): string {
  const a = new Uint32Array(2);
  crypto.getRandomValues(a);
  return `${Date.now().toString(36)}${a[0].toString(36)}${a[1].toString(36)}`;
}

export function isCaseDescription(d: unknown): boolean {
  return typeof d === 'string' && d.startsWith(CASE_PREFIX);
}

const STATUS_SET = new Set<string>(STATUSES);
const SEVERITY_SET = new Set<string>(CASE_SEVERITIES);
const KIND_SET = new Set<string>(['hunt', 'flow', 'client', 'alert']);

const s = (v: unknown, max = 20_000): string => (typeof v === 'string' ? v.slice(0, max) : '');
const n = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

// The record is stored in a shared notebook, so it is validated field by
// field rather than trusted.
export function parseCase(description: unknown, fallbackTitle = ''): CaseRecord | null {
  if (!isCaseDescription(description)) return null;
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse((description as string).slice(CASE_PREFIX.length)) as Record<string, unknown>;
  } catch {
    return null;
  }
  const status = STATUS_SET.has(String(raw.status)) ? raw.status as CaseStatus : 'open';
  const severity = SEVERITY_SET.has(String(raw.severity)) ? raw.severity as CaseSeverity : 'medium';
  const links = Array.isArray(raw.links) ? raw.links : [];
  const timeline = Array.isArray(raw.timeline) ? raw.timeline : [];
  return {
    title: s(raw.title, 300) || fallbackTitle,
    status,
    severity,
    owner: s(raw.owner, 200),
    summary: s(raw.summary),
    links: links
      .filter((l): l is Record<string, unknown> => !!l && typeof l === 'object' && KIND_SET.has(String((l as Record<string, unknown>).kind)))
      .map(l => ({
        id: s(l.id, 100) || newId(),
        kind: l.kind as LinkKind,
        ref: s(l.ref, 300),
        ...(s(l.clientId, 100) ? { clientId: s(l.clientId, 100) } : {}),
        label: s(l.label, 500),
        addedBy: s(l.addedBy, 200),
        addedAt: n(l.addedAt),
        ...(l.data && typeof l.data === 'object' ? { data: l.data as Record<string, unknown> } : {}),
      })),
    timeline: timeline
      .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object')
      .map(e => ({
        id: s(e.id, 100) || newId(),
        kind: (s(e.kind, 20) || 'note') as EntryKind,
        at: n(e.at),
        by: s(e.by, 200),
        text: s(e.text),
      })),
  };
}

export function serializeCase(c: CaseRecord): string {
  return CASE_PREFIX + JSON.stringify(c);
}

export function entry(kind: EntryKind, by: string, text: string): TimelineEntry {
  return { id: newId(), kind, at: Date.now(), by, text };
}
