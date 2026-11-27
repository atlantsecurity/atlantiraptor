import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  NO_FILTER, categoryOf, cloudProvider, commonOs, facetCounts, facetsOf, matchesFilter, needsPrecondition,
  preconditionPlatforms,
} from './artifactFacets.ts';

describe('facetsOf', () => {
  it('reads the platform from the name', () => {
    assert.deepEqual(facetsOf({ name: 'Windows.EventLogs.RDPAuth', built_in: true }).platforms, ['windows']);
    assert.deepEqual(facetsOf({ name: 'Linux.Sys.Users' }).platforms, ['linux']);
    assert.deepEqual(facetsOf({ name: 'MacOS.System.Users' }).platforms, ['macos']);
    assert.deepEqual(facetsOf({ name: 'Custom.Windows.Foo' }).platforms, ['windows']);
    assert.deepEqual(facetsOf({ name: 'Atlant.Feed.Linux.Bar' }).platforms, ['linux']);
  });

  it('falls back to the precondition when the name does not say', () => {
    const a = { name: 'Atlant.Feed.LolbinPersistence', precondition: "SELECT OS From info() where OS = 'windows'" };
    assert.deepEqual(facetsOf(a).platforms, ['any']);
    assert.deepEqual(facetsOf(a, true).platforms, ['windows']);
    assert.deepEqual(facetsOf({
      name: 'Generic.Thing', sources: [{ precondition: "SELECT * FROM info() WHERE OS = 'linux'" }, { precondition: "OS = 'darwin'" }],
    }, true).platforms, ['linux', 'macos']);
    assert.deepEqual(facetsOf({ name: 'Generic.Detection.Yara.Glob' }, true).platforms, ['any']);
  });

  it('puts Cloud.<Provider> server artifacts under their provider', () => {
    const f = facetsOf({ name: 'Cloud.M365.SignIns', type: 'SERVER' });
    assert.deepEqual(f.platforms, ['cloud']);
    assert.equal(f.cloud, 'Microsoft 365');
    assert.equal(cloudProvider('Cloud.GoogleWorkspace.Logins'), 'Google Workspace');
    assert.equal(cloudProvider('Cloud.Okta.Sessions'), 'Okta');
    assert.equal(cloudProvider('Cloud.AWS.CloudTrail'), 'AWS');
    assert.equal(cloudProvider('Cloud.Snowflake.Logins'), 'Snowflake');
    assert.equal(cloudProvider('Windows.Cloud.X'), undefined);
    assert.deepEqual(facetsOf({ name: 'Server.Utils.Foo', type: 'SERVER' }).platforms, ['server']);
  });

  it('labels the source', () => {
    assert.equal(facetsOf({ name: 'Windows.Sys.Users', built_in: true }).source, 'builtin');
    assert.equal(facetsOf({ name: 'Custom.Windows.Sys.Users', built_in: false }).source, 'custom');
    assert.equal(facetsOf({ name: 'Atlant.Feed.A', built_in: false }).source, 'premium');
  });
});

describe('categoryOf', () => {
  it('groups the segment after the platform', () => {
    assert.equal(categoryOf('Windows.EventLogs.RDPAuth'), 'Event logs');
    assert.equal(categoryOf('Windows.ETW.DNS'), 'Event logs');
    assert.equal(categoryOf('Linux.Sys.Users'), 'System');
    assert.equal(categoryOf('Generic.Forensic.Timeline'), 'Forensics');
    assert.equal(categoryOf('Custom.Windows.Detection.Foo'), 'Detection');
    assert.equal(categoryOf('Triage.Collection.Upload'), 'Triage');
    assert.equal(categoryOf('Windows.Whatever.X'), 'Other');
  });
});

describe('needsPrecondition', () => {
  it('only for client artifacts whose name names no single OS', () => {
    assert.equal(needsPrecondition('Windows.Sys.Users'), false);
    assert.equal(needsPrecondition('Generic.Client.Info'), true);
    assert.equal(needsPrecondition('Atlant.Feed.A'), true);
    assert.equal(needsPrecondition('Cloud.M365.SignIns', 'SERVER'), false);
  });
});

describe('filtering', () => {
  const all = [
    facetsOf({ name: 'Windows.Sys.Users', built_in: true }),
    facetsOf({ name: 'Linux.Sys.Users', built_in: true }),
    facetsOf({ name: 'Generic.Detection.Yara.Glob', built_in: true }),
    facetsOf({ name: 'Atlant.Feed.Windows.Persistence' }),
    facetsOf({ name: 'Cloud.M365.SignIns', type: 'SERVER', built_in: true }),
    facetsOf({ name: 'Cloud.Okta.Sessions', type: 'SERVER', built_in: true }),
  ];

  it('includes cross-platform artifacts under each OS', () => {
    const win = all.filter(f => matchesFilter(f, { ...NO_FILTER, platform: 'windows' })).map(f => f.name);
    assert.deepEqual(win, ['Windows.Sys.Users', 'Generic.Detection.Yara.Glob', 'Atlant.Feed.Windows.Persistence']);
    const any = all.filter(f => matchesFilter(f, { ...NO_FILTER, platform: 'any' })).map(f => f.name);
    assert.deepEqual(any, ['Generic.Detection.Yara.Glob']);
  });

  it('counts each facet with the other filters applied', () => {
    const c = facetCounts(all, { ...NO_FILTER, platform: 'windows', source: 'premium' });
    assert.equal(c.platform.get('all'), 1);
    assert.equal(c.platform.get('windows'), 1);
    assert.equal(c.platform.get('linux'), undefined);
    assert.equal(c.source.get('builtin'), 2);
    assert.equal(c.source.get('premium'), 1);
    const cloud = facetCounts(all, { ...NO_FILTER, platform: 'cloud' });
    assert.equal(cloud.cloud.get('Microsoft 365'), 1);
    assert.equal(cloud.cloud.get('Okta'), 1);
    assert.equal(cloud.platform.get('cloud'), 2);
  });
});

describe('commonOs', () => {
  it('finds the one OS every selected artifact needs', () => {
    assert.equal(commonOs([facetsOf({ name: 'Windows.A.B' }), facetsOf({ name: 'Custom.Windows.C' })]), 'windows');
    assert.equal(commonOs([facetsOf({ name: 'Windows.A.B' }), facetsOf({ name: 'Generic.C.D' })]), undefined);
    assert.equal(commonOs([facetsOf({ name: 'Windows.A.B' }), facetsOf({ name: 'Linux.C.D' })]), undefined);
    assert.equal(commonOs([facetsOf({ name: 'Windows.A.B' }), undefined]), undefined);
  });
});

describe('preconditionPlatforms', () => {
  it('reads each OS once', () => {
    assert.deepEqual(preconditionPlatforms(["OS = 'windows' OR OS = 'windows'"]), ['windows']);
    assert.deepEqual(preconditionPlatforms([undefined]), ['any']);
  });
});
