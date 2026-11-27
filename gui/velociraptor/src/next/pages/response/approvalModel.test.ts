import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { Hunt } from '../../lib/types.ts';
import {
  decodeUserData, encodeUserData, isPaused, oneLine, oneOffLabelOf, oneOffMismatch, requestView, selfApprovalReason,
} from './approvalModel.ts';

const LABEL = 'response-abcdef0123456789';

function hunt(p: Partial<Hunt> & { start_request?: Record<string, unknown> }): Hunt {
  return { hunt_id: 'H.1', ...p } as unknown as Hunt;
}

const spec = (artifact: string, env: [string, string][] = []) =>
  ({ artifact, parameters: { env: env.map(([key, value]) => ({ key, value })) } });

describe('user data', () => {
  it('round-trips and rejects junk', () => {
    const s = encodeUserData({ reason: 'case 12', requested_by: 'alice', one_off_label: LABEL });
    assert.deepEqual(decodeUserData(s), { reason: 'case 12', requested_by: 'alice', one_off_label: LABEL });
    assert.equal(decodeUserData('not json'), null);
    assert.equal(decodeUserData('{"other":1}'), null);
    assert.equal(decodeUserData(undefined), null);
  });

  it('oneLine collapses newlines and caps length', () => {
    assert.equal(oneLine('a\n(dry run)\n  b'), 'a (dry run) b');
    assert.equal(oneLine('x'.repeat(500)).length, 120);
  });
});

describe('oneOffLabelOf', () => {
  const ud = encodeUserData({ reason: 'r', requested_by: 'a', one_off_label: LABEL });

  it('accepts exactly the recorded one-off label', () => {
    const h = hunt({ condition: { labels: { label: [LABEL] } }, start_request: { user_data: ud } });
    assert.equal(oneOffLabelOf(h), LABEL);
  });

  it('rejects extra labels, OS or exclusions', () => {
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: [LABEL, 'finance'] } }, start_request: { user_data: ud } })), null);
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: [LABEL] }, os: { os: 'WINDOWS' } }, start_request: { user_data: ud } })), null);
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: [LABEL] }, excluded_labels: { label: ['x'] } }, start_request: { user_data: ud } })), null);
  });

  it('rejects a label that does not match the recorded one or the strict format', () => {
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: ['response-zzzzzzzzzzzzzzzz'] } }, start_request: { user_data: ud } })), null);
    const bad = encodeUserData({ reason: 'r', requested_by: 'a', one_off_label: 'response-' });
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: ['response-'] } }, start_request: { user_data: bad } })), null);
    assert.equal(oneOffLabelOf(hunt({ condition: { labels: { label: [LABEL] } } })), null);
  });
});

describe('requestView', () => {
  it('resolves specs per launched artifact and detects live', () => {
    const v = requestView(hunt({ start_request: {
      artifacts: ['Generic.Remediation.KillProcess'],
      specs: [spec('Generic.Remediation.KillProcess', [['ProcessRegex', 'evil'], ['ReallyDoIt', 'Y']])],
    } }));
    assert.deepEqual(v.problems, []);
    assert.equal(v.specs[0].live, true);
    assert.deepEqual(v.specs[0].params, [['ProcessRegex', 'evil'], ['ReallyDoIt', 'Y']]);
  });

  it('treats a dry run as not live and an artifact without a switch as live', () => {
    const dry = requestView(hunt({ start_request: { artifacts: ['A'], specs: [spec('A', [['ReallyDoIt', 'N']])] } }));
    assert.equal(dry.specs[0].live, false);
    const noSwitch = requestView(hunt({ start_request: { artifacts: ['Windows.Remediation.Quarantine'], specs: [] } }));
    assert.equal(noSwitch.specs[0].live, true);
    assert.equal(noSwitch.specs[0].hasSpec, false);
  });

  it('flags every shape that could make display differ from execution', () => {
    const problems = (start_request: Record<string, unknown>) => requestView(hunt({ start_request })).problems;
    assert.ok(problems({ artifacts: ['A', 'A'], specs: [] }).some(p => /more than once/.test(p)));
    assert.ok(problems({ artifacts: ['A'], specs: [spec('A'), spec('A')] }).some(p => /more than one parameter set/.test(p)));
    assert.ok(problems({ artifacts: ['A'], specs: [spec('B', [['ReallyDoIt', 'N']])] }).some(p => /not launched/.test(p)));
    assert.ok(problems({ artifacts: ['A'], specs: [spec('A', [['X', '1'], ['X', '2']])] }).some(p => /set twice/.test(p)));
    assert.ok(problems({ artifacts: ['A'], specs: [], allow_custom_overrides: true }).some(p => /overrides/.test(p)));
    assert.ok(problems({ artifacts: [], specs: [] }).some(p => /no artifacts/.test(p)));
  });

  it('a hidden armed spec for another artifact is a problem, not silently ignored', () => {
    const v = requestView(hunt({ start_request: {
      artifacts: ['A'], specs: [spec('A', [['ReallyDoIt', 'N']]), spec('B', [['ReallyDoIt', 'Y']])],
    } }));
    assert.equal(v.specs.length, 1);
    assert.ok(v.problems.length > 0);
  });
});

describe('isPaused', () => {
  it('accepts the enum name or number only', () => {
    assert.equal(isPaused(hunt({ state: 'PAUSED' as Hunt['state'] })), true);
    assert.equal(isPaused(hunt({ state: 1 as unknown as Hunt['state'] })), true);
    assert.equal(isPaused(hunt({ state: 'RUNNING' as Hunt['state'] })), false);
  });
});

describe('self approval', () => {
  const ud = (owner?: string) => encodeUserData({ reason: 'r', requested_by: 'api-0123456789abcdef', key_owner: owner });
  it('refuses the requester', () => {
    assert.ok(selfApprovalReason(hunt({ creator: 'alice' }), 'alice'));
  });
  it('refuses the creator of the API key, case-insensitively', () => {
    const h = hunt({ creator: 'api-0123456789abcdef', start_request: { user_data: ud('Alice') } });
    assert.ok(selfApprovalReason(h, 'alice'));
    assert.equal(selfApprovalReason(h, 'bob'), null);
  });
  it('allows anyone else for console requests', () => {
    assert.equal(selfApprovalReason(hunt({ creator: 'alice', start_request: { user_data: ud() } }), 'bob'), null);
  });
});
describe('one-off label hosts', () => {
  it('single-host requests need exactly one host', () => {
    assert.equal(oneOffMismatch(null, ['C.1']), null);
    assert.ok(oneOffMismatch(null, ['C.1', 'C.2']));
    assert.ok(oneOffMismatch(null, []));
  });
  it('several-host requests need exactly the recorded hosts', () => {
    assert.equal(oneOffMismatch(['C.1', 'C.2'], ['C.2', 'C.1']), null);
    assert.ok(oneOffMismatch(['C.1', 'C.2'], ['C.1']));
    assert.ok(oneOffMismatch(['C.1', 'C.2'], ['C.1', 'C.2', 'C.3']));
  });
});
