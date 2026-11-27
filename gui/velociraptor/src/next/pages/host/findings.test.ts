import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { findings, timeline } from './findings.ts';

describe('triage findings', () => {
  it('flags processes, persistence and connections worth a look', () => {
    const f = findings({
      'Windows.System.Pslist': [
        { Name: 'svchost.exe', Pid: 4, Exe: 'C:\\Windows\\System32\\svchost.exe', Authenticode: { Trusted: 'trusted' } },
        { Name: 'upd.exe', Pid: 66, Exe: 'C:\\Users\\bob\\AppData\\Roaming\\upd.exe', Authenticode: { Trusted: 'untrusted' } },
      ],
      'Windows.Network.Netstat': [
        { Name: 'upd.exe', Raddr: { IP: '203.0.113.7', Port: 443 } },
        { Name: 'x', Raddr: { IP: '10.0.0.2', Port: 445 } },
      ],
      'Windows.System.TaskScheduler/Analysis': [
        { TaskName: '\\Updater', Command: 'C:\\ProgramData\\u\\run.exe' },
        { TaskName: '\\MS', Command: 'C:\\Windows\\system32\\x.exe' },
      ],
    });
    const ids = f.map(x => x.id).sort();
    assert.deepEqual(ids, ['net-external', 'persist-scheduled task', 'proc-path', 'proc-unsigned']);
    assert.equal(f.find(x => x.id === 'net-external')!.rows.length, 1);
    assert.match(f.find(x => x.id === 'persist-scheduled task')!.summary(f.find(x => x.id === 'persist-scheduled task')!.rows[0]), /Updater/);
  });

  it('finds nothing in a clean host', () => {
    assert.deepEqual(findings({ 'Linux.Sys.Pslist': [{ Name: 'bash', Exe: '/usr/bin/bash' }] }), []);
  });

  it('builds a newest-first timeline', () => {
    const t = timeline({
      'Windows.System.Pslist': [{ Name: 'a', Pid: 1, CreateTime: '2026-11-01T10:00:00Z' }],
      'Windows.Forensics.Prefetch': [{ Executable: 'B.EXE', LastRunTimes: ['2026-11-02T10:00:00Z', '2026-10-01T10:00:00Z'] }],
    });
    assert.deepEqual(t.map(e => e.what), ['Program ran', 'Process started', 'Program ran']);
  });
});
