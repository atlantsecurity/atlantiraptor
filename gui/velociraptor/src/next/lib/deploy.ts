// Client for /api/v1/atl/deploy: the org's client configuration and
// ready-made install commands and scripts (Clients > Deploy a client).
// Server administrators only; the server enforces that.
import { useQuery } from '@tanstack/react-query';
import * as api from './api';

export interface DeployInfo {
  org_id: string;
  org_name: string;
  server_urls: string[];
  local_only: boolean;
  version: string;
  download_url: string;
  release_base: string;
  client_config: string;
  config_sha256: string;
  self_signed: boolean;
  commands: { windows: string; linux: string; macos: string };
  intune: { install_command: string; uninstall_command: string; setup_file: string };
  files: string[];
}

export function useDeployInfo(enabled: boolean) {
  return useQuery({
    queryKey: ['deploy-info', api.currentOrgId()],
    enabled,
    retry: false,
    staleTime: 5 * 60_000,
    queryFn: ({ signal }) => api.get<DeployInfo>('v1/atl/deploy', {}, signal),
  });
}

/** Downloads one of the deploy files (scripts, config, Intune package). */
export async function downloadDeployFile(name: string): Promise<void> {
  const base = api.basePath().replace(/\/+$/, '');
  const resp = await fetch(`${base}/api/v1/atl/deploy?file=${encodeURIComponent(name)}`, {
    headers: api.headers(), credentials: 'same-origin',
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({})) as { message?: string };
    throw new Error(body.message || `Could not download ${name} (HTTP ${resp.status})`);
  }
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
