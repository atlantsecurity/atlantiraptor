import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

type Win = { location: URL & { pathname: string }; base_path?: string; globals: { OrgId?: string } };

function setWindow(href: string, base: string | undefined, org?: string) {
  (globalThis as unknown as { window: Win }).window = {
    location: new URL(href) as Win['location'], base_path: base, globals: { OrgId: org },
  };
}

const { basePath, href, srcOf } = await import('./urls.ts');

describe('urls without a base path', () => {
  beforeEach(() => setWindow('https://srv.example:8889/app/index.html?org_id=root#/hunts', '', 'root'));
  it('links server paths and adds the org', () => {
    assert.equal(basePath(), '');
    assert.equal(srcOf('/downloads/x.zip'), '/downloads/x.zip');
    assert.equal(href('/api/v1/DownloadVFSFile', { fs_components: 'a' }),
      'https://srv.example:8889/api/v1/DownloadVFSFile?fs_components=a&org_id=root');
  });
  it('points console links at the app page and refuses other schemes', () => {
    assert.equal(href('/app/index.html', {}), 'https://srv.example:8889/app/index.html?org_id=root');
    assert.equal(href('javascript:alert(1)'), '#');
  });
});

describe('urls under a base path', () => {
  beforeEach(() => setWindow('https://srv.example/atl/app/index.html#/hunts', '/atl', 'O123'));
  it('puts the base path in front once', () => {
    assert.equal(basePath(), '/atl');
    assert.equal(srcOf('/downloads/x.zip'), '/atl/downloads/x.zip');
    assert.equal(srcOf('/atl/downloads/x.zip'), '/atl/downloads/x.zip');
    assert.equal(href('/api/v1/GetTable', { a: 1 }), 'https://srv.example/atl/api/v1/GetTable?a=1&org_id=O123');
    assert.equal(href('/atl/app/logoff.html', { username: 'bob' }), 'https://srv.example/atl/app/logoff.html?username=bob&org_id=O123');
  });
  it('derives the base path from the page when none is set', () => {
    setWindow('https://srv.example/sub/app/index.html', '', 'root');
    assert.equal(basePath(), '/sub');
  });
});
