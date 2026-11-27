import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FEED_HUNT_TAG, feedHuntRequest } from './model.ts';
import type { FeedPack } from '../../lib/feeds';

const pack: FeedPack = {
  id: 'atl-lolbin-persistence', name: 'LOLBin persistence', version: 3,
  artifacts: ['Atlant.Feed.A', 'Atlant.Feed.B'],
  hunt: { artifacts: ['Atlant.Feed.A'], os: 'windows', expires_hours: 24, cpu_limit: 30 },
  installed: true,
};

describe('feedHuntRequest', () => {
  const now = Date.UTC(2026, 10, 27);
  it('builds a running, tagged hunt for the pack', () => {
    const r = feedHuntRequest(pack, { os: 'windows', hours: 24, parameters: { 'Atlant.Feed.A': { X: '1' } } }, now);
    assert.deepEqual(r.tags, [FEED_HUNT_TAG, 'atl-lolbin-persistence']);
    assert.deepEqual(r.start_request.artifacts, ['Atlant.Feed.A']);
    assert.deepEqual(r.start_request.specs, [{ artifact: 'Atlant.Feed.A', parameters: { env: [{ key: 'X', value: '1' }] } }]);
    assert.deepEqual(r.condition, { os: { os: 'WINDOWS' } });
    assert.equal(r.expires, (now + 24 * 3600 * 1000) * 1000);
    assert.equal(r.state, 2);
    assert.equal(r.start_request.cpu_limit, 30);
    assert.match(r.hunt_description ?? '', /LOLBin persistence \(v3\)/);
  });
  it('targets every client and every artifact when the pack does not narrow it', () => {
    const r = feedHuntRequest({ ...pack, hunt: {} }, { os: '', hours: 0, parameters: {} }, now);
    assert.equal(r.condition, undefined);
    assert.deepEqual(r.start_request.artifacts, ['Atlant.Feed.A', 'Atlant.Feed.B']);
    assert.ok((r.expires ?? 0) > (now + 5 * 365 * 24 * 3600 * 1000) * 1000, 'runs until stopped');
  });
});
