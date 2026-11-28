import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { planFor, sourceDone, ROWS_PER_SOURCE } from './triageLoad.ts';
import { areas } from './triageSummary.ts';

describe('triage loading', () => {
  it('asks only for what the checks read', () => {
    assert.equal(planFor('Windows.Registry.AppCompatCache').countOnly, true);
    assert.equal(planFor('Windows.Registry.UserAssist').rows, 1);
    assert.ok(!planFor('Windows.Forensics.Prefetch').columns!.includes('FilesAccessed'));
    assert.deepEqual(planFor('Windows.Forensics.Amcache/InventoryApplicationFile').columns!.slice(0, 2), ['FullPath', 'SHA1']);
    // Linux Pslist and unknown artifacts: every column.
    assert.equal(planFor('Linux.Sys.Pslist').columns, undefined);
    assert.equal(planFor('Windows.Network.Netstat').rows, ROWS_PER_SOURCE);
  });

  it('reads a source once its query has finished', () => {
    const stats = [
      { names_with_response: ['Windows.System.Pslist'] },                        // OK (zero value, omitted)
      { status: 'PROGRESS', names_with_response: ['Windows.Forensics.Prefetch'] },
      { names_with_response: ['Linux.Sys.Crontab/CronTabs', 'Linux.Sys.Crontab/CronScripts'] },
    ];
    assert.equal(sourceDone('Windows.System.Pslist', true, stats), true);
    assert.equal(sourceDone('Windows.Forensics.Prefetch', true, stats), false);
    assert.equal(sourceDone('Linux.Sys.Crontab/Uploaded', true, stats), true);
    assert.equal(sourceDone('Windows.Network.Netstat', true, stats), false);
    assert.equal(sourceDone('Windows.Forensics.Prefetch', false, stats), true);
  });

  it('counts rows that were not downloaded', () => {
    const a = areas({ 'Windows.Registry.AppCompatCache': [] }, [], { 'Windows.Registry.AppCompatCache': 1500 });
    assert.equal(a[0].rows, 1500);
  });
});
