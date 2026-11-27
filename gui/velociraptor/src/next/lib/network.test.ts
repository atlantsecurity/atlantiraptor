import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { coveredBy, entryProblem, splitEntries } from './networkModel.ts';

describe('network entries', () => {
  it('validates entries', () => {
    for (const ok of ['10.0.0.0/8', '192.0.2.7', '2001:db8::/32', '0.0.0.0/0']) assert.equal(entryProblem(ok), null, ok);
    for (const bad of ['10.0.0.0/33', 'host.example', '300.1.1.1', '1.2.3.4/x']) assert.ok(entryProblem(bad), bad);
  });
  it('splits free text', () => {
    assert.deepEqual(splitEntries('10.0.0.0/8, 192.0.2.7\n10.0.0.0/8'), ['10.0.0.0/8', '192.0.2.7']);
  });
  it('checks coverage', () => {
    assert.equal(coveredBy('10.2.3.4', ['10.0.0.0/8']), true);
    assert.equal(coveredBy('11.2.3.4', ['10.0.0.0/8', '192.0.2.7']), false);
    assert.equal(coveredBy('192.0.2.7', ['192.0.2.7']), true);
    assert.equal(coveredBy('8.8.8.8', ['0.0.0.0/0']), true);
    assert.equal(coveredBy('2001:db8::1', ['10.0.0.0/8']), null);
  });
});

