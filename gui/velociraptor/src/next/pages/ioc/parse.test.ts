import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { classify, parseIocs, refang, toCsv } from './parse.ts';

describe('classify', () => {
  it('recognises each indicator type', () => {
    assert.equal(classify('44d88612fea8a8f36de82e1278abb02f'), 'md5');
    assert.equal(classify('a'.repeat(40)), 'sha1');
    assert.equal(classify('B'.repeat(64)), 'sha256');
    assert.equal(classify('185.220.101.4'), 'ip');
    assert.equal(classify('2001:db8::1'), 'ip');
    assert.equal(classify('C:\\ProgramData\\x\\svc.exe'), 'path');
    assert.equal(classify('/tmp/.x/payload'), 'path');
    assert.equal(classify('evil-c2.example'), 'domain');
    assert.equal(classify('invoice_2024.js'), 'filename');
    assert.equal(classify('setup.exe'), 'filename');
    assert.equal(classify('not an ioc'), null);
    assert.equal(classify('999.1.1.1'), null);
  });
});

describe('refang', () => {
  it('undoes common defanging', () => {
    assert.equal(refang('hxxps://bad[.]example/p'), 'https://bad.example/p');
    assert.equal(refang('evil(.)example'), 'evil.example');
    assert.equal(refang('a[dot]b'), 'a.b');
  });
});

describe('parseIocs', () => {
  it('normalises, de-duplicates and reports rejects', () => {
    const r = parseIocs([
      'hxxps://Bad.Example/payload', 'bad[.]example', 'EVIL.example', 'evil.example',
      'domain,Forced.Example,"note, with comma"', '# comment', '', 'garbage here',
    ].join('\n'));
    assert.deepEqual(r.iocs.map(i => `${i.type}:${i.value}`), ['domain:bad.example', 'domain:evil.example', 'domain:forced.example']);
    assert.equal(r.iocs[2].note, 'note, with comma');
    assert.deepEqual(r.rejected, ['garbage here']);
  });

  it('keeps path and filename case', () => {
    const r = parseIocs('C:\\Users\\Public\\Evil.EXE\nInvoice.JS');
    assert.deepEqual(r.iocs.map(i => i.value), ['C:\\Users\\Public\\Evil.EXE', 'Invoice.JS']);
  });
});

describe('toCsv', () => {
  it('quotes cells that need it', () => {
    const csv = toCsv([{ type: 'domain', value: 'a.example', note: 'x, "y"' }]);
    assert.equal(csv, 'Type,Value,Note\ndomain,a.example,"x, ""y"""\n');
  });
});
