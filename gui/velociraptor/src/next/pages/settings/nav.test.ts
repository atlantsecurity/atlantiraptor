import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SETTINGS_PAGES, activeSettingsPage, isSettingsPath } from './nav.ts';

describe('settings navigation', () => {
  it('covers the admin pages under their existing addresses', () => {
    for (const p of ['/users', '/users/alice', '/groups', '/account/security', '/secrets/AWS', '/integrations',
      '/apikeys', '/network', '/updates', '/orgs', '/settings', '/settings/https', '/settings/deploy', '/settings/audit']) {
      assert.ok(isSettingsPath(p), p);
    }
  });
  it('does not claim other pages', () => {
    for (const p of ['/dashboard', '/hunts', '/usersx', '/networking', '/search/all', '/', '/settingsx']) {
      assert.equal(isSettingsPath(p), false, p);
    }
  });
  it('finds the page for an address', () => {
    assert.equal(activeSettingsPage('/users/bob')?.id, 'users');
    assert.equal(activeSettingsPage('/settings/https')?.id, 'https');
    assert.equal(activeSettingsPage('/settings/audit')?.id, 'audit');
    assert.equal(activeSettingsPage('/settings'), undefined);
  });
  it('has unique ids and addresses', () => {
    assert.equal(new Set(SETTINGS_PAGES.map(p => p.id)).size, SETTINGS_PAGES.length);
    assert.equal(new Set(SETTINGS_PAGES.map(p => p.to)).size, SETTINGS_PAGES.length);
  });
});
