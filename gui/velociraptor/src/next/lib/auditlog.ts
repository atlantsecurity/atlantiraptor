// Client for the tamper-evident audit log (/api/v1/atl/audit, see
// services/auditlog). Server administrators only.
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface AuditHead { seq: number; hash: string; time: string; key_id: string }

export interface AuditProblem { severity: 'error' | 'warning'; file?: string; seq?: number; message: string }

export interface AuditVerify {
  ok: boolean;
  directory: string;
  files: number;
  entries: number;
  first_time?: string;
  last_time?: string;
  last_seq: number;
  checkpoints: number;
  last_checkpoint_seq: number;
  last_checkpoint_time?: string;
  unsigned_tail: number;
  key_ids: string[];
  errors: number;
  warnings: number;
  problems: AuditProblem[];
  checked: number;
  duration_ms: number;
}

export interface AuditSettings {
  directory: string;
  syslog: { enabled: boolean; server: string; protocol: 'udp' | 'tcp' | 'tls' | string };
  updated_by?: string;
  updated?: number;
}

export interface AuditStatus {
  enabled: boolean;
  reason?: string;
  directory: string;
  directory_source: 'env' | 'settings' | 'default';
  default_directory: string;
  env_override: boolean;
  key_id?: string;
  public_key?: string;
  head: AuditHead;
  files: number;
  bytes: number;
  last_verify?: AuditVerify;
  verifying: boolean;
  write_errors: number;
  last_write_error?: string;
  settings: AuditSettings;
  forward: { active: boolean; sent: number; dropped: number; last_error?: string };
}

export interface AuditEntry {
  seq: number;
  time: string;
  type: 'event' | 'genesis' | 'checkpoint' | 'key' | 'recovered';
  org_id?: string;
  principal?: string;
  operation?: string;
  details?: unknown;
  public_key?: string;
  key_id?: string;
  prev: string;
  hash: string;
  sig?: string;
}

export interface AuditFilter {
  from?: string; // ISO
  to?: string;
  principal?: string;
  operation?: string;
  org?: string;
  q?: string;
  checkpoints?: boolean;
}

const KEY = ['audit-log'];
const PAGE = 200;

export function useAuditStatus() {
  return useQuery({
    queryKey: [...KEY, 'status'],
    queryFn: ({ signal }) => api.get<AuditStatus>('v1/atl/audit', { view: 'status' }, signal),
    refetchInterval: q => (q.state.data?.verifying ? 2000 : 30000),
  });
}

/** Query parameters for a filter (empty values left out). */
export function filterParams(f: AuditFilter): Record<string, string> {
  const out: Record<string, string> = {};
  if (f.from) out.from = new Date(f.from).toISOString().replace(/\.\d{3}Z$/, 'Z');
  if (f.to) out.to = new Date(f.to).toISOString().replace(/\.\d{3}Z$/, 'Z');
  for (const k of ['principal', 'operation', 'org', 'q'] as const) {
    const v = f[k]?.trim();
    if (v) out[k] = v;
  }
  if (f.checkpoints) out.checkpoints = '1';
  return out;
}

export function useAuditEntries(f: AuditFilter, enabled: boolean) {
  const params = filterParams(f);
  return useInfiniteQuery({
    queryKey: [...KEY, 'entries', params],
    enabled,
    initialPageParam: 0,
    placeholderData: keepPreviousData,
    queryFn: ({ pageParam, signal }) => api.get<{ entries: AuditEntry[]; more: boolean }>('v1/atl/audit', {
      view: 'entries', limit: PAGE, ...params, ...(pageParam ? { before: pageParam } : {}),
    }, signal),
    getNextPageParam: last => (last.more && last.entries.length ? last.entries[last.entries.length - 1].seq : undefined),
    refetchInterval: 30000,
  });
}

export function useAuditAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: { action: 'verify' } | { action: 'settings'; settings: AuditSettings }) =>
      api.post<AuditStatus>('v1/atl/audit', p),
    onSuccess: d => {
      qc.setQueryData([...KEY, 'status'], d);
      qc.invalidateQueries({ queryKey: [...KEY, 'entries'] });
    },
  });
}

/** Downloads the filtered log as JSONL (lines exactly as stored) or CSV. */
export async function downloadAudit(f: AuditFilter, format: 'jsonl' | 'csv'): Promise<void> {
  const base = api.basePath().replace(/\/+$/, '');
  const qs = new URLSearchParams({ view: 'export', format, ...filterParams(f) });
  const resp = await fetch(`${base}/api/v1/atl/audit?${qs}`, { headers: api.headers(), credentials: 'same-origin' });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({})) as { message?: string };
    throw new Error(body.message || `Export failed (HTTP ${resp.status})`);
  }
  const name = /filename="([^"]+)"/.exec(resp.headers.get('Content-Disposition') ?? '')?.[1] ?? `audit.${format}`;
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** One line summary of an entry's details for the table. */
export function detailsSummary(d: unknown, max = 160): string {
  if (d == null) return '';
  if (typeof d !== 'object') return String(d).slice(0, max);
  const parts: string[] = [];
  for (const [k, v] of Object.entries(d as Record<string, unknown>)) {
    if (v == null || v === '' || k === 'queued_at') continue;
    const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
    parts.push(`${k}=${s}`);
  }
  const out = parts.join('  ');
  return out.length > max ? out.slice(0, max - 1) + '…' : out;
}
