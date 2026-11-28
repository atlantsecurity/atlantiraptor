import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { safeHttpUrl } from './safeUrl.ts';

describe('safeHttpUrl', () => {
  it('keeps http and https links', () => {
    assert.equal(safeHttpUrl('https://example.com/a?b=1'), 'https://example.com/a?b=1');
    assert.equal(safeHttpUrl(' http://example.com '), 'http://example.com/');
  });

  it('refuses other schemes, relative and broken values', () => {
    for (const v of ['javascript:alert(1)', 'JavaScript:alert(1)', 'data:text/html,x', 'vbscript:x',
      'file:///etc/passwd', '/relative', 'not a url', '', undefined, null]) {
      assert.equal(safeHttpUrl(v), null, String(v));
    }
  });
});
