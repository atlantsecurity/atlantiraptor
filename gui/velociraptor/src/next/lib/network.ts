// Client for the network allowlists (/api/v1/atl/network). The server
// enforces them; this only drives the admin screen.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface NetworkList { enabled: boolean; entries: string[] }
export interface NetworkPolicy { console: NetworkList; api: NetworkList; updated?: number; updated_by?: string }
export interface NetworkView {
  policy: NetworkPolicy;
  your_ip: string;
  your_ip_is_local: boolean;
  break_glass_active: boolean;
  static_cidrs?: string[];
  proxy_warning?: boolean;
}

export function useNetworkPolicy() {
  return useQuery({
    queryKey: ['network-policy'],
    queryFn: ({ signal }) => api.get<NetworkView>('v1/atl/network', {}, signal),
  });
}

export function useSaveNetworkPolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: { policy: NetworkPolicy; confirm_lockout?: boolean }) => api.post<NetworkView>('v1/atl/network', p),
    onSuccess: d => qc.setQueryData(['network-policy'], d),
  });
}

export { coveredBy, entryProblem, splitEntries } from './networkModel';

