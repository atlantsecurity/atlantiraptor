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

export interface ConnectionInfo {
  cert_name: string;
  cert_names: string[];
  cert_expires?: number;
  port: number;
  bind_address: string;
  loopback_only: boolean;
  has_ca: boolean;
}

interface KeysResponse { keys: ApiKey[]; roles: string[]; connection?: ConnectionInfo }
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

/** Downloads the server's CA certificate (public) as a .pem file. */
export async function downloadCaCertificate(): Promise<void> {
  const resp = await fetch(`${api.basePath().replace(/\/+$/, '')}/api/v1/atl/apikeys?ca=1`, {
    headers: api.headers(), credentials: 'same-origin',
  });
  if (!resp.ok) throw new Error(`Could not download the certificate (HTTP ${resp.status})`);
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = 'atlantiraptor-ca.pem';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export interface TestResult { ok: boolean; message: string }

/** Calls the REST API with a key, exactly as an integration would. */
export async function testApiKey(token: string): Promise<TestResult> {
  try {
    const who = await fetch(`${apiBaseUrl()}/whoami`, { headers: { Authorization: `Bearer ${token}` }, credentials: 'omit' });
    const body = await who.json().catch(() => ({})) as { error?: string; key?: { roles?: string[] } };
    if (!who.ok) return { ok: false, message: body.error || `HTTP ${who.status}` };
    const actions = await fetch(`${apiBaseUrl()}/actions`, { headers: { Authorization: `Bearer ${token}` }, credentials: 'omit' });
    const list = await actions.json().catch(() => ({})) as { data?: unknown[] };
    if (!actions.ok) return { ok: false, message: `Key works but the action list failed (HTTP ${actions.status})` };
    return { ok: true, message: `Key accepted with roles ${(body.key?.roles ?? []).join(', ')}; ${list.data?.length ?? 0} actions available.` };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}