import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CASE_PREFIX, isCaseDescription, parseCase, serializeCase, type CaseRecord } from './model.ts';

const record: CaseRecord = {
  title: 'Suspicious service', status: 'in_progress', severity: 'high', owner: 'alice', summary: 's',
  links: [{ id: 'l1', kind: 'hunt', ref: 'H.1', label: 'H.1', addedBy: 'alice', addedAt: 1 }],
  timeline: [{ id: 't1', kind: 'note', at: 2, by: 'alice', text: 'hello' }],
};

describe('case record', () => {
  it('round-trips', () => {
    const d = serializeCase(record);
    assert.ok(isCaseDescription(d));
    assert.deepEqual(parseCase(d), record);
  });

  it('ignores ordinary notebooks and broken JSON', () => {
    assert.equal(parseCase('A normal notebook description'), null);
    assert.equal(parseCase(`${CASE_PREFIX}{not json`), null);
    assert.equal(isCaseDescription(undefined), false);
  });

  it('replaces invalid values with safe defaults and drops unknown link kinds', () => {
    const d = CASE_PREFIX + JSON.stringify({
      title: 'x', status: 'hacked', severity: 'apocalyptic',
      links: [{ kind: 'javascript', ref: 'x' }, { kind: 'client', ref: 'C.1', label: 'host' }, null],
      timeline: [42, { kind: 'note', text: 'ok' }],
    });
    const c = parseCase(d);
    assert.ok(c);
    assert.equal(c.status, 'open');
    assert.equal(c.severity, 'medium');
    assert.deepEqual(c.links.map(l => l.kind), ['client']);
    assert.equal(c.timeline.length, 1);
  });

  it('caps oversized fields', () => {
    const c = parseCase(CASE_PREFIX + JSON.stringify({ title: 't'.repeat(1000), summary: 's'.repeat(50_000) }));
    assert.ok(c);
    assert.equal(c.title.length, 300);
    assert.equal(c.summary.length, 20_000);
  });
});
