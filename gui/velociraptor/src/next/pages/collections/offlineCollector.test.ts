import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { collectorProblems, collectorRequest, defaultCollectorForm, COLLECTOR_ARTIFACT } from './offlineCollector.ts';

const envOf = (r: ReturnType<typeof collectorRequest>) =>
  Object.fromEntries(r.specs[0].parameters.env.map(e => [e.key, e.value]));

describe('offline collector request', () => {
  it('builds a CreateCollector request with the chosen options', () => {
    const f = { ...defaultCollectorForm(), artifacts: ['Windows.KapeFiles.Targets', 'Generic.Client.Info'],
      parameters: { 'Windows.KapeFiles.Targets': { _SANS_Triage: 'Y' } }, os: 'Linux' as const };
    const r = collectorRequest(f);
    assert.deepEqual(r.artifacts, [COLLECTOR_ARTIFACT]);
    const env = envOf(r);
    assert.equal(env.OS, 'Linux');
    assert.deepEqual(JSON.parse(env.artifacts), ['Windows.KapeFiles.Targets', 'Generic.Client.Info']);
    assert.deepEqual(JSON.parse(env.parameters), { 'Windows.KapeFiles.Targets': { _SANS_Triage: 'Y' } });
    assert.equal(env.target, 'ZIP');
    assert.equal(env.encryption_scheme, 'None');
    assert.equal(env.opt_prompt, 'N');
    assert.equal(env.opt_filename_template, 'Collection-%Hostname%-%TIMESTAMP%');
    // Empty optional fields are left out so the artifact defaults apply.
    assert.equal('opt_tempdir' in env, false);
  });

  it('sends only the fields of the chosen target', () => {
    const f = { ...defaultCollectorForm(), artifacts: ['Generic.Client.Info'], target: 'S3' as const,
      targetArgs: { bucket: ' evidence ', region: 'eu-west-1', sas_url: 'leftover', privatekey: 'x' } };
    assert.deepEqual(JSON.parse(envOf(collectorRequest(f)).target_args), { bucket: 'evidence', region: 'eu-west-1' });
  });

  it('passes the encryption arguments for the chosen scheme only', () => {
    const base = { ...defaultCollectorForm(), artifacts: ['Generic.Client.Info'], password: 'p', publicKey: 'k' };
    assert.deepEqual(JSON.parse(envOf(collectorRequest({ ...base, encryption: 'Password' })).encryption_args), { password: 'p' });
    assert.deepEqual(JSON.parse(envOf(collectorRequest({ ...base, encryption: 'X509' })).encryption_args), { public_key: 'k' });
    assert.deepEqual(JSON.parse(envOf(collectorRequest(base)).encryption_args), {});
  });
});

describe('offline collector problems', () => {
  it('needs artifacts, required target fields and a password', () => {
    const f = { ...defaultCollectorForm(), target: 'GCS' as const, encryption: 'Password' as const };
    const p = collectorProblems(f);
    assert.ok(p.some(x => /artifact/.test(x)));
    assert.ok(p.some(x => /Bucket/.test(x)));
    assert.ok(p.some(x => /Service account key/.test(x)));
    assert.ok(p.some(x => /password/.test(x)));
  });

  it('checks numeric options', () => {
    const f = { ...defaultCollectorForm(), artifacts: ['A'], level: '12', cpuLimit: 'abc' };
    const p = collectorProblems(f);
    assert.ok(p.some(x => /Compression level is 0 to 9/.test(x)));
    assert.ok(p.some(x => /CPU limit must be a whole number/.test(x)));
  });

  it('is happy with the defaults plus an artifact', () => {
    assert.deepEqual(collectorProblems({ ...defaultCollectorForm(), artifacts: ['Generic.Client.Info'] }), []);
  });
});
