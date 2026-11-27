// Alerts arrive in the Server.Internal.Alerts event queue, raised by
// alert() calls in client or server artifacts. This module turns raw
// queue rows into typed alerts the dashboard can sort and act on.
import type { Row } from '../../../lib/table';
import { toDate } from '../../../lib/format';

export const ALERTS_ARTIFACT = 'Server.Internal.Alerts';
export const SIGMA_MONITOR = 'Windows.Detection.SigmaMonitor';
export const YARA_MONITOR = 'Generic.Detection.YaraMonitor';
export const TEST_ALERT = 'Generic.Detection.TestAlert';
export const DETECTION_MONITORS = [SIGMA_MONITOR, YARA_MONITOR];

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const SEVERITY_TONE: Record<Severity, 'bad' | 'warn' | 'accent' | 'info' | 'neutral'> = {
  critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: 'neutral',
};

export interface Alert {
  key: string;
  // Stable across reloads (unlike key): used to remember triage state.
  id: string;
  name: string;
  time: Date | null;
  clientId: string;
  artifact: string;
  artifactType: string;
  flowId: string;
  severity: Severity;
  source: string;
  rule: string;
  description: string;
  data: Record<string, unknown>;
}

function asObject(v: unknown): Record<string, unknown> {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v as Record<string, unknown>;
  if (typeof v === 'string') {
    try {
      const parsed: unknown = JSON.parse(v);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // Not JSON: keep it as a single field below.
    }
    return v ? { value: v } : {};
  }
  return {};
}

function asSeverity(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'low') return 'low';
  if (s === 'informational' || s === 'info') return 'info';
  return 'medium';
}

const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v));

/** Short FNV-1a hash, enough to tell alerts with the same name and time apart. */
export function shortHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

export function toAlert(r: Row, index: number): Alert {
  const data = asObject(r.event_data);
  const time = toDate((r.timestamp ?? r._ts) as string | number);
  const clientId = str(r.client_id);
  return {
    key: `${clientId}-${str(r.timestamp)}-${str(r.name)}-${index}`,
    id: `${clientId}|${str(r.timestamp)}|${str(r.name)}|${shortHash(JSON.stringify(r.event_data ?? ''))}`,
    name: str(r.name) || 'Alert',
    time,
    clientId,
    artifact: str(r.artifact),
    artifactType: str(r.artifact_type),
    flowId: str(r.flow_id),
    severity: asSeverity(data.level),
    source: str(data.source),
    rule: str(data.rule) || str(r.name),
    description: str(data.description),
    data,
  };
}

// Where the event behind an alert can be inspected: a monitoring
// artifact's event table, or the collection the alert came from.
export function sourceLink(a: Alert): string | null {
  if (!a.clientId) return null;
  if (a.flowId && a.artifactType !== 'CLIENT_EVENT') return `/collected/${a.clientId}/${a.flowId}`;
  if (a.artifact) return `/events/${a.clientId}/${a.artifact}`;
  return null;
}

// Fields shown in the expanded alert, in a stable, useful order.
const HIDDEN = new Set(['source', 'level', 'rule', 'description']);
export function detailEntries(a: Alert): [string, unknown][] {
  return Object.entries(a.data).filter(([k]) => !HIDDEN.has(k));
}
