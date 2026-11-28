import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buttonHref, inlineTable } from './cellData.ts';

describe('inlineTable', () => {
  const data = JSON.stringify({
    table0: { Response: JSON.stringify([{ X: 1, Y: 2 }]), Columns: ['X', 'Y'] },
    table1: { Response: '[{"A":1}]' },
  });
  it('finds the rows a chart points at', () => {
    assert.deepEqual(inlineTable(data, "data['table0']"), { rows: [{ X: 1, Y: 2 }], columns: ['X', 'Y'] });
    assert.deepEqual(inlineTable(data, encodeURIComponent("data['table1']")), { rows: [{ A: 1 }], columns: ['A'] });
  });
  it('returns null for missing or broken data', () => {
    assert.equal(inlineTable(data, "data['nope']"), null);
    assert.equal(inlineTable(undefined, "data['table0']"), null);
    assert.equal(inlineTable('not json', "data['table0']"), null);
    assert.equal(inlineTable(data, ''), null);
  });
});

describe('buttonHref', () => {
  it('allows console and web links only', () => {
    assert.equal(buttonHref('#/hunts/H.1'), '#/hunts/H.1');
    assert.equal(buttonHref('/collected/C.1'), '#/collected/C.1');
    assert.equal(buttonHref('https://example.com/x'), 'https://example.com/x');
    assert.equal(buttonHref('javascript:alert(1)'), null);
    assert.equal(buttonHref('//evil.example'), null);
    assert.equal(buttonHref(''), null);
  });
});
