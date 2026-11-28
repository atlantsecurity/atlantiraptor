import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fleetVersions } from './summary.ts';

describe('fleetVersions', () => {
  const counts = [
    { os: 'windows', version: '1.0.5', count: 3 },
    { os: 'windows', version: '1.0.10', count: 2 },
    { os: 'windows', version: 'unknown', count: 1 },
    { os: 'linux', version: '0.77.4', count: 4 },
  ];

  it('finds the newest version per OS, numerically', () => {
    const v = fleetVersions(counts);
    assert.deepEqual(v.latestByOs, { windows: '1.0.10', linux: '0.77.4' });
  });

  it('counts outdated agents per OS and never flags unknown or another OS', () => {
    const v = fleetVersions(counts);
    assert.deepEqual(v.outdatedByOs, { windows: { count: 3, versions: ['1.0.5'] } });
    assert.equal(v.outdatedTotal, 3);
    assert.equal(v.rows.find(r => r.version === 'unknown')?.outdated, false);
    assert.equal(v.rows.find(r => r.os === 'linux')?.latest, true);
  });

  it('sorts by OS, newest first, unknown last', () => {
    const v = fleetVersions(counts);
    assert.deepEqual(v.rows.map(r => `${r.os}/${r.version}`),
      ['linux/0.77.4', 'windows/1.0.10', 'windows/1.0.5', 'windows/unknown']);
  });

  it('handles an empty fleet', () => {
    const v = fleetVersions([]);
    assert.deepEqual(v.rows, []);
    assert.equal(v.outdatedTotal, 0);
  });
});
