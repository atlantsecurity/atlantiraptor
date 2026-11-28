// Client for agent certificates on the agent port and blocking agents
// (/api/v1/atl/agent-mtls). The checks run in the server's TLS
// handshake; this only drives the admin screens.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export type AgentMtlsMode = 'off' | 'warn' | 'enforce';

export interface AgentMtlsSettings {
  mode: AgentMtlsMode;
  allow_enrollment: boolean;
  allow_legacy: boolean;
  updated_by?: string;
  updated?: number;
}

export type AgentCertKind = 'own' | 'new' | 'legacy' | 'none' | 'other';

export interface AgentMtlsListed {
  client_id: string; org_id: string; hostname?: string; version?: string;
  kind: AgentCertKind; last_seen: number; remote?: string;
}

export interface AgentMtlsBlocked {
  client_id: string; org_id?: string; hostname?: string; reason?: string; by?: string; time: number;
}

export interface AgentMtlsRejection {
  time: number; remote: string; client_id?: string; reason: string; refused: boolean;
}

export interface AgentMtlsStatus {
  settings: AgentMtlsSettings;
  effective_mode: AgentMtlsMode;
  unavailable?: string;
  disabled_by_env?: boolean;
  frontend_up: boolean;
  console_exposed?: boolean;
  console_bind?: string;
  deployment?: { serial: string; created: number; created_by?: string; from_config?: boolean };
  counts: { seen: number; own: number; new: number; legacy: number; none: number; other: number };
  not_ready: AgentMtlsListed[];
  would_refuse: number;
  blocked: AgentMtlsBlocked[];
  rejections: AgentMtlsRejection[];
  window_seconds: number;
}

const KEY = ['agent-mtls'];

export function useAgentMtlsStatus(enabled = true) {
  return useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => api.get<AgentMtlsStatus>('v1/atl/agent-mtls', {}, signal),
    refetchInterval: 30000,
    enabled,
    retry: false,
  });
}

export type AgentMtlsAction =
  | { action: 'settings'; settings: AgentMtlsSettings; force?: boolean }
  | { action: 'rotate' }
  | { action: 'block'; client_id: string; org_id: string; reason: string }
  | { action: 'unblock'; client_id: string };

export function useAgentMtlsAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: AgentMtlsAction) => api.post<AgentMtlsStatus>('v1/atl/agent-mtls', p),
    onSuccess: d => qc.setQueryData(KEY, d),
  });
}

// The base client ID (without the org suffix) that blocking works on.
export function baseClientId(id: string): string {
  return id.split('-')[0];
}

export function isBlocked(status: AgentMtlsStatus | undefined, clientId: string): boolean {
  const base = baseClientId(clientId);
  return !!status?.blocked.some(b => b.client_id === base);
}

export const KIND_LABEL: Record<AgentCertKind, string> = {
  own: 'Own certificate',
  new: 'Enrolling',
  legacy: 'Deployment certificate only (older agent)',
  none: 'No certificate (older agent)',
  other: 'Certificate of another agent',
};
