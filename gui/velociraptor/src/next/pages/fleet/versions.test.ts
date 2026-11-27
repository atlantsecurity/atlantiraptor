import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions } from './versions.ts';

describe('compareVersions', () => {
  it('compares numerically, not as text', () => {
    assert.ok(compareVersions('0.77.10', '0.77.4') > 0);
    assert.ok(compareVersions('0.77.4', '0.77.10') < 0);
    assert.equal(compareVersions('0.77.4', '0.77.4'), 0);
  });

  it('treats missing parts as zero and tolerates suffixes', () => {
    assert.equal(compareVersions('0.77', '0.77.0'), 0);
    assert.ok(compareVersions('0.78-rc1', '0.77.9') > 0);
    assert.ok(compareVersions('1.0.0', '0.99.99') > 0);
  });
});
