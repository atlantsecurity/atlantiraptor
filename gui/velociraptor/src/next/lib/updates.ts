// Client for the server's self-update from GitHub releases
// (/api/v1/atl/update). The server does the checking, verifying and
// installing; this only drives the admin screen.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface UpdateSettings { auto_install: boolean; check_hours: number; updated_by?: string; updated?: number }
export interface UpdateStatus {
  running: boolean;
  current_version: string;
  dev_build: boolean;
  platform: string;
  install_supported: boolean;
  repository: string;
  settings: UpdateSettings;
  auto_disabled_by_env?: boolean;
  latest_version?: string;
  latest_url?: string;
  latest_published?: string;
  latest_has_binary: boolean;
  update_available: boolean;
  last_check?: number;
  next_check?: number;
  last_error?: string;
  state: 'idle' | 'checking' | 'downloading' | 'verifying' | 'restarting';
  last_result?: string;
}

const KEY = ['server-update'];

export function useUpdateStatus() {
  return useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => api.get<UpdateStatus>('v1/atl/update', {}, signal),
    refetchInterval: q => (q.state.data && q.state.data.state !== 'idle' ? 2000 : 30000),
  });
}

export function useUpdateAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: { action: 'check' | 'install' } | ({ action: 'settings' } & Pick<UpdateSettings, 'auto_install' | 'check_hours'>)) =>
      api.post<UpdateStatus>('v1/atl/update', p),
    onSuccess: d => qc.setQueryData(KEY, d),
  });
}
