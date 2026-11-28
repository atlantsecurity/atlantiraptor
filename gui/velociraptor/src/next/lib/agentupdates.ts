// Client for automatic agent upgrades (/api/v1/atl/agent-update). The
// server picks the version, hosts the signed binary and schedules the
// upgrades; this only drives the admin screen.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface AgentUpdateSettings {
  enabled: boolean;
  pinned_version?: string;
  canary_percent: number;
  canary_hours: number;
  exclude_label: string;
  updated_by?: string;
  updated?: number;
}

export interface AgentUpdateCounts {
  clients: number;
  windows: number;
  up_to_date: number;
  waiting: number;
  offline: number;
  upgrading: number;
  retrying: number;
  failed: number;
  excluded: number;
  newer: number;
  unsupported: number;
  canary: number;
  canary_done: number;
  versions: Record<string, number>;
  platforms: Record<string, number>;
}

export interface AgentUpdateFailed {
  org_id: string; client_id: string; hostname: string; version: string;
  attempts: number; error: string; flow_id?: string;
}

export interface AgentUpdateStatus {
  running: boolean;
  state: 'idle' | 'disabled' | 'error' | 'rolling out' | 'paused' | 'done';
  reason?: string;
  server_version: string;
  target?: string;
  settings: AgentUpdateSettings;
  disabled_by_env?: boolean;
  phase?: 'canary' | 'all' | 'paused';
  phase_changed?: number;
  started?: number;
  canary_until?: number;
  paused_reason?: string;
  binary?: { version: string; sha256: string; size: number; signer: string; source: string; prepared: number };
  counts: AgentUpdateCounts;
  failed: AgentUpdateFailed[];
  last_tick?: number;
  next_tick?: number;
  last_error?: string;
  last_scheduled: number;
  supported_os: string[];
  artifact_name: string;
  tool_name: string;
}

const KEY = ['agent-update'];

export function useAgentUpdateStatus() {
  return useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => api.get<AgentUpdateStatus>('v1/atl/agent-update', {}, signal),
    refetchInterval: 30000,
  });
}

export type AgentUpdateAction =
  | { action: 'resume' | 'retry_failed' | 'run' }
  | { action: 'settings'; settings: AgentUpdateSettings };

export function useAgentUpdateAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: AgentUpdateAction) => api.post<AgentUpdateStatus>('v1/atl/agent-update', p),
    onSuccess: d => qc.setQueryData(KEY, d),
  });
}
