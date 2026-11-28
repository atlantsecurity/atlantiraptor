// Two-person approval for live response actions.
//
// When the policy is on, a live action is created as a PAUSED hunt tagged
// approval:pending. A different user approves it (which starts it) or
// rejects it (which stops it). The server audit log records who did each
// step; tags and user_data are set by the browser and are not proof.
//
// This is a workflow, not a server-enforced control: anyone with the
// START_HUNT permission can still start hunts through the API.
import { useMemo } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import * as api from '../../lib/api';
import { setServerMetadata, useHunts, useServerMetadata } from '../../lib/queries';
import type { Hunt } from '../../lib/types';
import { RESPONSE_TAG } from './actions';
import { MAX_PICKED_CLIENTS } from './ClientPicker';
import {
  APPROVED_PREFIX, isPaused, oneOffClientsOf, oneOffLabelOf, PENDING_TAG, POLICY_KEY, REJECTED_PREFIX, selfApprovalReason,
} from './approvalModel';

export * from './approvalModel';

// Policy is on when the key says so, and also while it is loading or
// cannot be read, so a live action never skips approval by accident.
// A missing key means off: the policy is opt-in.
export function useApprovalPolicy() {
  const q = useServerMetadata();
  const value = q.data?.[POLICY_KEY];
  return {
    loaded: q.isSuccess || q.isError,
    readable: q.isSuccess,
    required: !q.isSuccess || value === 'Y',
    set: async (on: boolean) => {
      await setServerMetadata(POLICY_KEY, on ? 'Y' : 'N');
      await q.refetch();
    },
  };
}

export function usePendingApprovals() {
  const { data: hunts = [] } = useHunts(false);
  return useMemo(() => hunts.filter(h =>
    (h.tags ?? []).includes(RESPONSE_TAG) && (h.tags ?? []).includes(PENDING_TAG)), [hunts]);
}

async function freshHunt(id: string): Promise<Hunt> {
  return api.get<Hunt>('v1/GetHunt', { hunt_id: id, include_request: true });
}

export function useApprovalActions() {
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: ['hunts'] });

  // Re-read the hunt right before acting: it must still be paused and
  // pending, so a stale view cannot restart a rejected request. The
  // server enforces the same rules (hunt_dispatcher/approval_guard.go).
  const decide = async (id: string, me: string, approve: boolean) => {
    if (!me) throw new Error('Your user name is not loaded yet. Try again in a moment.');
    const h = await freshHunt(id);
    if (!(h.tags ?? []).includes(PENDING_TAG) || !isPaused(h)) {
      refresh();
      throw new Error('This request was already decided or changed. The list has been refreshed.');
    }
    const self = approve ? selfApprovalReason(h, me) : null;
    if (self) throw new Error(self);
    // One change: the server only accepts the decision together with
    // the new state, recorded for the signed-in user.
    const tags = [...(h.tags ?? []).filter(t => t !== PENDING_TAG), `${approve ? APPROVED_PREFIX : REJECTED_PREFIX}${me}`];
    await api.post('v1/ModifyHunt', { hunt_id: id, state: approve ? 'RUNNING' : 'STOPPED', tags });
    if (!approve) await removeOneOffLabels(h);
    refresh();
  };

  return {
    approve: (id: string, me: string) => decide(id, me, true),
    reject: (id: string, me: string) => decide(id, me, false),
  };
}

// The single-host approval path labels the host with a one-off label;
// drop exactly that label, from exactly that one host, once the request
// is rejected. Anything else is left alone.
export async function removeOneOffLabels(h: Hunt) {
  const label = oneOffLabelOf(h);
  if (!label) return;
  const expected = oneOffClientsOf(h);
  const found = await api.get<{ items?: { client_id: string }[] }>('v1/SearchClients',
    { query: `label:${label}`, limit: Math.min((expected?.length ?? 1) + 5, MAX_PICKED_CLIENTS + 5) });
  const ids = (found.items ?? []).map(c => c.client_id);
  // Only from the hosts the request named (or the one host of a
  // single-host request).
  const targets = expected ? ids.filter(id => expected.includes(id)) : ids.length === 1 ? ids : [];
  if (targets.length) await api.post('v1/LabelClients', { client_ids: targets, labels: [label], operation: 'remove' });
}