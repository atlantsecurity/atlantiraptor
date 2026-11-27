import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  addSuppression, isOpen, parseTriage, removeSuppression, serializeTriage, setState, stateOf, suppressedBy,
} from './triage.ts';
import type { Alert } from './model.ts';

const alert = (id: string, rule = 'Mimikatz', clientId = 'C.1') =>
  ({ id, rule, clientId } as unknown as Alert);

describe('alert triage', () => {
  it('defaults to new and open', () => {
    const r = parseTriage('');
    assert.equal(stateOf(r, alert('a')).status, 'new');
    assert.ok(isOpen(r, alert('a')));
  });

  it('round-trips and drops old states', () => {
    const now = Date.now();
    let r = setState(parseTriage(''), ['a'], { status: 'closed' }, 'alice', now);
    r = setState(r, ['old'], { status: 'closed' }, 'bob', now - 30 * 24 * 3600 * 1000);
    const back = parseTriage(serializeTriage(r, now));
    assert.equal(back.states.a.status, 'closed');
    assert.equal(back.states.a.by, 'alice');
    assert.equal(back.states.old, undefined);
    assert.equal(isOpen(back, alert('a')), false);
  });

  it('keeps the assignee when the status changes', () => {
    let r = setState(parseTriage(''), ['a'], { assignee: 'alice' }, 'bob');
    r = setState(r, ['a'], { status: 'acknowledged' }, 'alice');
    assert.equal(r.states.a.assignee, 'alice');
    assert.ok(isOpen(r, alert('a')));
  });

  it('suppresses by rule, optionally per host', () => {
    let r = addSuppression(parseTriage(''), { rule: 'Mimikatz', clientId: 'C.1', by: 'alice' });
    assert.ok(suppressedBy(r, alert('a', 'Mimikatz', 'C.1')));
    assert.equal(suppressedBy(r, alert('b', 'Mimikatz', 'C.2')), undefined);
    r = addSuppression(r, { rule: 'Mimikatz', clientId: 'C.1', by: 'bob' });
    assert.equal(r.suppress.length, 1);
    r = removeSuppression(r, r.suppress[0].id);
    assert.equal(r.suppress.length, 0);
  });

  it('ignores broken data', () => {
    assert.deepEqual(parseTriage('atl-alerts:v1:{nope'), { states: {}, suppress: [] });
    assert.deepEqual(parseTriage('atl-alerts:v1:{"states":{"x":{"status":"bogus"}}}').states, {});
  });
});
