// Shared alert triage state: status, assignee and suppression rules.
// Stored as the description of one public notebook, the same way cases
// are, so every analyst sees the same queue. Pure helpers (no React, no
// network) so they can be unit tested.
import type { Alert } from './model';

export const TRIAGE_PREFIX = 'atl-alerts:v1:';
export const TRIAGE_NOTEBOOK_NAME = 'Alert triage (used by the dashboard)';

export type AlertStatus = 'new' | 'acknowledged' | 'closed' | 'false_positive';
export const ALERT_STATUSES: AlertStatus[] = ['new', 'acknowledged', 'closed', 'false_positive'];
export const ALERT_STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'New', acknowledged: 'Acknowledged', closed: 'Closed', false_positive: 'False positive',
};
export const ALERT_STATUS_TONE: Record<AlertStatus, 'warn' | 'accent' | 'neutral' | 'info'> = {
  new: 'warn', acknowledged: 'accent', closed: 'neutral', false_positive: 'info',
};

export interface AlertState {
  status: AlertStatus;
  assignee?: string;
  by: string;
  at: number; // ms since epoch
}

export interface Suppression {
  id: string;
  rule: string;
  clientId?: string; // only on this host when set
  by: string;
  at: number;
  reason?: string;
}

export interface TriageRecord {
  states: Record<string, AlertState>;
  suppress: Suppression[];
}

export const EMPTY_TRIAGE: TriageRecord = { states: {}, suppress: [] };

// Alerts are shown for 7 days; keep their state a little longer.
const KEEP_MS = 14 * 24 * 3600 * 1000;

export function isTriageDescription(d: unknown): boolean {
  return typeof d === 'string' && d.startsWith(TRIAGE_PREFIX);
}

export function parseTriage(d: unknown): TriageRecord {
  if (!isTriageDescription(d)) return { states: {}, suppress: [] };
  try {
    const raw = JSON.parse((d as string).slice(TRIAGE_PREFIX.length)) as Partial<TriageRecord>;
    const states: Record<string, AlertState> = {};
    for (const [k, v] of Object.entries(raw.states ?? {})) {
      if (v && (ALERT_STATUSES as string[]).includes(v.status)) states[k] = v;
    }
    const suppress = Array.isArray(raw.suppress) ? raw.suppress.filter(s => s && typeof s.rule === 'string') : [];
    return { states, suppress };
  } catch {
    return { states: {}, suppress: [] };
  }
}

export function serializeTriage(r: TriageRecord, now = Date.now()): string {
  const states: Record<string, AlertState> = {};
  for (const [k, v] of Object.entries(r.states)) if (now - v.at < KEEP_MS) states[k] = v;
  return TRIAGE_PREFIX + JSON.stringify({ states, suppress: r.suppress });
}

export function stateOf(r: TriageRecord, a: Alert): AlertState {
  return r.states[a.id] ?? { status: 'new', by: '', at: 0 };
}

export function suppressedBy(r: TriageRecord, a: Alert): Suppression | undefined {
  return r.suppress.find(s => s.rule === a.rule && (!s.clientId || s.clientId === a.clientId));
}

/** Open = still needs someone: new or acknowledged, and not suppressed. */
export function isOpen(r: TriageRecord, a: Alert): boolean {
  const s = stateOf(r, a).status;
  return (s === 'new' || s === 'acknowledged') && !suppressedBy(r, a);
}

export function setState(r: TriageRecord, ids: string[], change: Partial<AlertState>, by: string, now = Date.now()): TriageRecord {
  const states = { ...r.states };
  for (const id of ids) {
    const cur = states[id] ?? { status: 'new' as AlertStatus, by, at: now };
    states[id] = { ...cur, ...change, by, at: now };
  }
  return { ...r, states };
}

export function addSuppression(r: TriageRecord, s: Omit<Suppression, 'id' | 'at'>, now = Date.now()): TriageRecord {
  if (r.suppress.some(x => x.rule === s.rule && (x.clientId ?? '') === (s.clientId ?? ''))) return r;
  const id = `${now.toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  return { ...r, suppress: [...r.suppress, { ...s, id, at: now }] };
}

export function removeSuppression(r: TriageRecord, id: string): TriageRecord {
  return { ...r, suppress: r.suppress.filter(s => s.id !== id) };
}
