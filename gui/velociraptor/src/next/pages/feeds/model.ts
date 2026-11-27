// Building the hunt for a feed pack (kept free of React so it can be
// unit tested with node --test).
import type { CreateHuntRequest } from '../../lib/queries';
import type { FeedPack } from '../../lib/feeds';
import { untilStoppedExpiry } from '../hunts/time.ts';

/** Tag on every hunt started from a feed pack (plus the pack id). */
export const FEED_HUNT_TAG = 'atlant-feed';

export interface FeedHuntOptions {
  os: '' | 'windows' | 'linux' | 'darwin';
  hours: number; // 0 = until stopped
  parameters: Record<string, Record<string, string>>;
}

const HUNT_OS = { windows: 'WINDOWS', linux: 'LINUX', darwin: 'OSX' } as const;

/** The CreateHunt request for a pack, as the launch dialog configured it. */
export function feedHuntRequest(pack: FeedPack, o: FeedHuntOptions, now = Date.now()): CreateHuntRequest {
  const artifacts = pack.hunt.artifacts?.length ? pack.hunt.artifacts : pack.artifacts;
  const specs = artifacts.map(artifact => ({
    artifact,
    parameters: { env: Object.entries(o.parameters[artifact] ?? {}).map(([key, value]) => ({ key, value })) },
  }));
  const req: CreateHuntRequest = {
    hunt_description: `${pack.hunt.description || `Atlant feed: ${pack.name}`} (v${pack.version})`,
    tags: [FEED_HUNT_TAG, pack.id],
    start_request: { artifacts, specs },
    condition: o.os ? { os: { os: HUNT_OS[o.os] } } : undefined,
    expires: o.hours > 0 ? (now + o.hours * 3600 * 1000) * 1000 : untilStoppedExpiry(now),
    state: 2,
  };
  if (pack.hunt.cpu_limit) req.start_request.cpu_limit = pack.hunt.cpu_limit;
  if (pack.hunt.timeout) req.start_request.timeout = pack.hunt.timeout;
  return req;
}
