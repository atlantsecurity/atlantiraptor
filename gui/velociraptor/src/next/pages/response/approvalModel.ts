// Pure approval logic (no React, no network), kept separate so it can be
// unit tested. See approval.ts for the workflow around it.
import type { Hunt } from '../../lib/types';

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
  // For requests made with an API key: who created the key.
  key_owner?: string;
  api_key?: string;
}

// The approver must be someone other than the requester, and for API
// key requests someone other than the person who created the key.
export function selfApprovalReason(h: Hunt, me: string): string | null {
  if (h.creator === me) return 'You cannot approve your own request. Ask another user.';
  const owner = requestOf(h)?.key_owner;
  if (owner && owner.toLowerCase() === me.toLowerCase()) {
    return 'This request came from an API key you created, so another user must approve it.';
  }
  return null;
}

const ONE_OFF_RE = /^response-[0-9a-z]{12,40}$/;

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

export function requestOf(h: Hunt): ResponseUserData | null {
  return decodeUserData(h.start_request?.user_data);
}

export function isPaused(h: Hunt): boolean {
  const s = h.state as unknown;
  return s === 'PAUSED' || s === HUNT_PAUSED;
}

export interface SpecView { artifact: string; params: [string, string][]; duplicateKeys: boolean; live: boolean; hasSpec: boolean }
export interface RequestView { specs: SpecView[]; problems: string[] }

// The request as the launcher will run it: one entry per launched
// artifact, using its spec (or defaults when it has none). Anything that
// could make the display differ from execution is reported as a problem
// that blocks approval. A request is live if any artifact is armed or has
// no dry-run switch.
export function requestView(h: Hunt): RequestView {
  const req = h.start_request ?? {};
  const artifacts = req.artifacts ?? [];
  const specs = req.specs ?? [];
  const problems: string[] = [];
  const names = specs.map(s => s.artifact ?? '');
  if (new Set(artifacts).size !== artifacts.length) problems.push('An artifact is launched more than once.');
  if (new Set(names).size !== names.length) problems.push('An artifact has more than one parameter set.');
  if (names.some(n => !artifacts.includes(n))) problems.push('Parameters are given for an artifact that is not launched.');
  if ((req as { allow_custom_overrides?: boolean }).allow_custom_overrides) problems.push('The request overrides artifact definitions.');
  if (artifacts.length === 0) problems.push('The request launches no artifacts.');

  const view = artifacts.map(name => {
    const s = specs.find(x => x.artifact === name);
    const env = s?.parameters?.env ?? [];
    const keys = env.map(e => e.key);
    const arm = env.find(e => e.key === 'ReallyDoIt');
    return {
      artifact: name,
      params: env.map(e => [e.key, e.value] as [string, string]),
      duplicateKeys: new Set(keys).size !== keys.length,
      live: arm ? arm.value === 'Y' : true,
      hasSpec: !!s,
    };
  });
  if (view.some(v => v.duplicateKeys)) problems.push('An artifact has a parameter set twice.');
  return { specs: view, problems };
}
