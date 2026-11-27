import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { groupByHost, indicatorProblem } from './model.ts';

describe('indicatorProblem', () => {
  it('accepts domains, URLs and IPs', () => {
    for (const ok of ['example.com', 'sub.example.co.uk', 'https://evil.example/path?x=1', '203.0.113.7', '2001:db8::1', 'example.com/path']) {
      assert.equal(indicatorProblem(ok), null, ok);
    }
  });
  it('rejects junk', () => {
    for (const bad of ['two words', '300.1.1.1', 'nodot', 'http://', 'a|.*']) {
      assert.ok(indicatorProblem(bad), bad);
    }
  });
});

describe('groupByHost', () => {
  it('groups rows per machine with sources, users and newest first', () => {
    const rows = [
      { ClientId: 'C.1', Fqdn: 'pc1', Source: 'Browser history', Time: '2026-11-01T10:00:00Z', User: 'bob', Match: 'https://x/' },
      { ClientId: 'C.2', Fqdn: 'pc2', Source: 'Live connection', Time: 1795626497, Match: '1.2.3.4' },
      { ClientId: 'C.1', Fqdn: 'pc1', Source: 'DNS cache', Time: '2026-11-20T10:00:00Z', Match: 'x' },
      { Source: 'no client' },
    ];
    const g = groupByHost(rows);
    assert.equal(g.length, 2);
    assert.equal(g[0].clientId, 'C.2'); // epoch seconds 1795626497 is later than Nov 2026
    const pc1 = g.find(h => h.clientId === 'C.1')!;
    assert.deepEqual(pc1.sources, ['Browser history', 'DNS cache']);
    assert.deepEqual(pc1.users, ['bob']);
    assert.equal(pc1.hits[0].source, 'DNS cache');
  });
});

import { detectKind, kindProblem, parseRapidDescription, rapidDescription } from './model.ts';

describe('detectKind', () => {
  it('guesses the kind of indicator', () => {
    const cases: [string, string][] = [
      ['example.com', 'web'], ['https://evil.example/x', 'web'], ['hxxps://evil[.]example', 'web'],
      ['203.0.113.7', 'web'], ['2001:db8::1', 'web'],
      ['44d88612fea8a8f36de82e1278abb02f', 'hash'], ['a'.repeat(64), 'hash'],
      ['C:\\Users\\bob\\AppData\\x.exe', 'file'], ['/tmp/payload', 'file'], ['invoice.pdf', 'file'],
      ['rclone.exe', 'process'], ['mimikatz', 'process'],
      ['CORP\\alice', 'user'], ['alice@corp.example', 'user'],
    ];
    for (const [v, k] of cases) assert.equal(detectKind(v), k, v);
  });
  it('validates per kind', () => {
    assert.equal(kindProblem('abc', 'hash') !== null, true);
    assert.equal(kindProblem('a'.repeat(40), 'hash'), null);
    assert.equal(kindProblem('C:\\x.exe', 'process') !== null, true);
    assert.equal(kindProblem('rclone.exe', 'process'), null);
    assert.equal(kindProblem('CORP\\alice', 'user'), null);
  });
  it('round-trips descriptions', () => {
    assert.deepEqual(parseRapidDescription(rapidDescription('example.com', 'web')), { indicator: 'example.com', kind: 'web' });
    assert.deepEqual(parseRapidDescription(rapidDescription('CORP\\alice', 'user')), { indicator: 'CORP\\alice', kind: 'user' });
    assert.equal(parseRapidDescription('Sweep: Linux.Sys.Users'), null);
  });
});

import { pivotKind } from './model.ts';

describe('pivotKind', () => {
  it('uses the column name as a hint', () => {
    assert.equal(pivotKind('Username', 'CORP\\alice'), 'user');
    assert.equal(pivotKind('User', 'bob'), 'user');
    assert.equal(pivotKind('Name', 'svchost.exe'), 'process');
    assert.equal(pivotKind('Exe', 'C:\\Windows\\x.exe'), 'file');
    assert.equal(pivotKind('Hash', 'a'.repeat(64)), 'hash');
    assert.equal(pivotKind('Raddr', '203.0.113.7'), 'web');
  });
  it('skips values that are not indicators', () => {
    assert.equal(pivotKind('State', 'ESTABLISHED'), null);
    assert.equal(pivotKind('Detail', 'two\nlines'), null);
    assert.equal(pivotKind('Hash', 'nothex'), null);
  });
});
