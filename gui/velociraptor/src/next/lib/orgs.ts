// Organization management (Admin > Organizations). The server only
// answers org admins: administrators (or org admins) of the root org.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

import type { Org } from '../pages/orgs/model';

export type { Org };
export { ORG_NAME_MAX, orgNameProblem } from '../pages/orgs/model';

/** The URL that opens the console in another org. */
export function orgSwitchHref(orgId: string): string {
  return api.href('/app/index.html', { org_id: orgId }) + '#/dashboard';
}

export function orgClientConfigHref(orgId: string): string {
  return api.href('/api/v1/atl/orgs', { client_config: orgId });
}

export function useOrgs() {
  return useQuery({
    queryKey: ['orgs'],
    queryFn: ({ signal }) => api.get<{ orgs?: Org[] }>('v1/atl/orgs', {}, signal),
    select: d => [...(d.orgs ?? [])].sort((a, b) =>
      Number(!!b.root) - Number(!!a.root) || a.name.localeCompare(b.name)),
    retry: false,
  });
}

function useOrgMutation<P>(body: (p: P) => Record<string, unknown>, onDone?: () => void) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: P) => api.post<{ org?: Org; deleted?: string }>('v1/atl/orgs', body(p)),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['orgs'] });
      qc.invalidateQueries({ queryKey: ['global-users'] });
      onDone?.();
    },
  });
}

export function useCreateOrg(onDone?: () => void) {
  return useOrgMutation((p: { name: string }) => ({ action: 'create', name: p.name.trim() }), onDone);
}

export function useRenameOrg(onDone?: () => void) {
  return useOrgMutation((p: { id: string; name: string }) => ({ action: 'rename', id: p.id, name: p.name.trim() }), onDone);
}

export function useDeleteOrg(onDone?: () => void) {
  return useOrgMutation((p: { id: string; confirm: string }) => ({ action: 'delete', id: p.id, confirm: p.confirm }), onDone);
}
