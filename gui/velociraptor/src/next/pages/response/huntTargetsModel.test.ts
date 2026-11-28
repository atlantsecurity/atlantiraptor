import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { matchedHosts } from './huntTargetsModel.ts';

describe('matchedHosts', () => {
  it('keeps hosts with rows, once each, and falls back to the ID for a name', () => {
    const rows = [
      { ClientId: 'C.1', Hostname: 'alpha', TotalRows: '3' },
      { ClientId: 'C.2', Hostname: 'beta', TotalRows: '0' },
      { ClientId: 'C.3', Hostname: '', TotalRows: 1 },
      { ClientId: 'C.1', Hostname: 'alpha', TotalRows: 5 },
      { ClientId: '', TotalRows: 9 },
      { Hostname: 'no-id', TotalRows: 2 },
    ];
    assert.deepEqual(matchedHosts(rows), [
      { id: 'C.1', hostname: 'alpha' },
      { id: 'C.3', hostname: 'C.3' },
    ]);
  });

  it('returns nothing for no rows', () => {
    assert.deepEqual(matchedHosts([]), []);
  });
});
