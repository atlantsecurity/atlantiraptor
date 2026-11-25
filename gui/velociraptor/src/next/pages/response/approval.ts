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

export const POLICY_KEY = 'atl_response_require_approval';
export const PENDING_TAG = 'approval:pending';
export const APPROVED_PREFIX = 'approval:approved-by:';
export const REJECTED_PREFIX = 'approval:rejected-by:';
export const ONE_OFF_LABEL_PREFIX = 'response-';
export const HUNT_PAUSED = 1;

export interface ResponseUserData {
  reason: string;
  requested_by: string;
  approval?: 'required' | 'not-required';
  // The exact one-off label a single-host request was aimed at.
  one_off_label?: string;
}

const ONE_OFF_RE = /^response-[0-9a-z]{12,40}$/;

// A request counts as single-host only if the condition is exactly the
// one-off label recorded in the request, with no OS or exclusions.
export function oneOffLabelOf(h: Hunt): string | null {
  const recorded = decodeUserData(h.start_request?.user_data)?.one_off_label ?? '';
  const c = h.condition ?? {};
  const labels = c.labels?.label ?? [];
  if (!ONE_OFF_RE.test(recorded)) return null;
  if (labels.length !== 1 || labels[0] !== recorded) return null;
  if (c.os?.os || (c.excluded_labels?.label ?? []).length) return null;
  return recorded;
}

export function encodeUserData(d: ResponseUserData): string {
  return JSON.stringify({ atl_response: d });
}

export function decodeUserData(s: unknown): ResponseUserData | null {
  if (typeof s !== 'string' || !s) return null;
  try {
    const v = (JSON.parse(s) as { atl_response?: ResponseUserData }).atl_response;
    return v && typeof v.reason === 'string' ? v : null;
  } catch {
    return null;
  }
}

// Requester text placed in titles: one line, capped, so it cannot pass
// for system text such as "(dry run)" on a new line.
export function oneLine(s: string, max = 120): string {
  return s.replace(/\s+/g, ' ').trim().slice(0, max);
}

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

export function requestOf(h: Hunt): ResponseUserData | null {
  return decodeUserData(h.start_request?.user_data);
}

function isPaused(h: Hunt): boolean {
  const s = h.state as unknown;
  return s === 'PAUSED' || s === HUNT_PAUSED;
}

async function freshHunt(id: string): Promise<Hunt> {
  return api.get<Hunt>('v1/GetHunt', { hunt_id: id, include_request: true });
}

export function useApprovalActions() {
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: ['hunts'] });

  // Re-read the hunt right before acting: it must still be paused and
  // pending, so a stale view cannot restart a rejected request. The
  // state changes first; the decision tag follows.
  const decide = async (id: string, me: string, approve: boolean) => {
    if (!me) throw new Error('Your user name is not loaded yet. Try again in a moment.');
    const h = await freshHunt(id);
    if (!(h.tags ?? []).includes(PENDING_TAG) || !isPaused(h)) {
      refresh();
      throw new Error('This request was already decided or changed. The list has been refreshed.');
    }
    if (approve && h.creator === me) throw new Error('You cannot approve your own request. Ask another user.');
    await api.post('v1/ModifyHunt', { hunt_id: id, state: approve ? 'RUNNING' : 'STOPPED' });
    const tags = [...(h.tags ?? []).filter(t => t !== PENDING_TAG), `${approve ? APPROVED_PREFIX : REJECTED_PREFIX}${me}`];
    await api.post('v1/ModifyHunt', { hunt_id: id, tags });
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
  const found = await api.get<{ items?: { client_id: string }[] }>('v1/SearchClients',
    { query: `label:${label}`, limit: 2 });
  const ids = (found.items ?? []).map(c => c.client_id);
  if (ids.length === 1) await api.post('v1/LabelClients', { client_ids: ids, labels: [label], operation: 'remove' });
}

export interface SpecView { artifact: string; params: [string, string][]; duplicateKeys: boolean; live: boolean }

// Parameters per artifact, as the client will receive them. A request
// counts as live if any artifact is armed or has no dry-run switch.
export function specsOf(h: Hunt): SpecView[] {
  return (h.start_request?.specs ?? []).map(s => {
    const env = s.parameters?.env ?? [];
    const keys = env.map(e => e.key);
    const arm = env.find(e => e.key === 'ReallyDoIt');
    return {
      artifact: s.artifact ?? '',
      params: env.map(e => [e.key, e.value] as [string, string]),
      duplicateKeys: new Set(keys).size !== keys.length,
      live: arm ? arm.value === 'Y' : true,
    };
  });
}
