// Client for SIEM/SOAR API key management (/api/v1/atl/apikeys).
// Keys are created, scoped and enforced on the server.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface ApiKey {
  id: string;
  name: string;
  hint: string;
  roles: string[];
  org_id: string;
  created_by: string;
  created: number;
  expires?: number;
  last_used?: number;
  rate_limit?: number;
}

interface KeysResponse { keys: ApiKey[]; roles: string[] }
export interface NewKey { name: string; roles: string[]; ttl_days: number }
export interface CreatedKey { key: ApiKey; token: string }

export function useApiKeys() {
  return useQuery({
    queryKey: ['apikeys'],
    queryFn: ({ signal }) => api.get<KeysResponse>('v1/atl/apikeys', {}, signal),
  });
}

export function useCreateApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (k: NewKey) => api.post<CreatedKey>('v1/atl/apikeys', k),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['apikeys'] }),
  });
}

export function useRevokeApiKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<{ revoked: ApiKey }>('v1/atl/apikeys', { id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['apikeys'] }),
  });
}

/** The REST API base URL as seen from this browser. */
export function apiBaseUrl(): string {
  const base = api.basePath().replace(/\/+$/, '');
  return `${window.location.origin}${base}/api/atl/v1`;
}
