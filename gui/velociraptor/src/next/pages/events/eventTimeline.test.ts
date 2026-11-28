import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mergeTimeline, rowSeconds, summarize } from './eventTimeline.ts';

describe('rowSeconds', () => {
  it('reads seconds, milliseconds, microseconds, nanoseconds and ISO times', () => {
    assert.equal(rowSeconds({ _ts: 1_800_000_000 }), 1_800_000_000);
    assert.equal(rowSeconds({ _ts: 1_800_000_000_123 }), 1_800_000_000);
    assert.equal(rowSeconds({ Timestamp: '1800000000123456' }), 1_800_000_000);
    assert.equal(rowSeconds({ EventTime: 1_800_000_000_123_456_789 }), 1_800_000_000);
    assert.equal(rowSeconds({ Time: '2027-01-15T08:00:00Z' }), Date.UTC(2027, 0, 15, 8) / 1000);
    assert.equal(rowSeconds({ Other: 1 }), 0);
  });
});

describe('summarize', () => {
  it('skips time and empty fields and shortens long values', () => {
    const s = summarize({ _ts: 1, Name: 'x', Empty: '', Obj: { a: 1 }, Long: 'y'.repeat(100), More: 1, Extra: 2 });
    assert.equal(s.startsWith('Name: x · Obj: {"a":1} · Long: yyy'), true);
    assert.equal(s.includes('Empty'), false);
    assert.equal(s.includes('Extra'), false);
  });
});

describe('mergeTimeline', () => {
  it('merges artifacts newest first', () => {
    const t = mergeTimeline({
      'A.Events': [{ _ts: 100, X: 1 }, { _ts: 300, X: 2 }],
      'B.Events': [{ _ts: 200, Y: 1 }, { Y: 2 }],
    });
    assert.deepEqual(t.map(e => `${e.artifact}@${e.ts}`), ['A.Events@300', 'B.Events@200', 'A.Events@100', 'B.Events@0']);
  });
});
