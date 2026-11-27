// Client for Atlant Security's premium hunt feeds (/api/v1/atl/feeds).
// The server holds the licence key, fetches and verifies the signed
// feed and loads its packs as Atlant.Feed.* artifacts; this drives the
// Hunt feeds page.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface FeedHuntSpec {
  description?: string;
  artifacts?: string[];
  parameters?: Record<string, Record<string, string>>;
  os?: '' | 'windows' | 'linux' | 'darwin';
  expires_hours?: number;
  cpu_limit?: number;
  timeout?: number;
}

export interface FeedPack {
  id: string;
  name: string;
  version: number;
  published?: number;
  updated?: number;
  severity?: '' | 'info' | 'low' | 'medium' | 'high' | 'critical';
  category?: string;
  tags?: string[];
  platforms?: string[];
  summary?: string;
  description?: string;
  references?: string[];
  changes?: string;
  artifacts: string[];
  hunt: FeedHuntSpec;
  fresh?: '' | 'new' | 'updated';
  first_seen?: number;
  version_seen?: number;
  installed: boolean;
  install_error?: string;
}

export type FeedState = 'not_configured' | 'unlicensed' | 'pending' | 'active' | 'expired' | 'invalid';

export interface FeedStatus {
  running: boolean;
  state: FeedState;
  has_key: boolean;
  masked_key?: string;
  key_set_by?: string;
  key_set_at?: number;
  licence?: { id?: string; customer?: string; plan?: string; expires?: number };
  feed?: string;
  issued?: number;
  usable_until?: number;
  last_sync?: number;
  next_sync?: number;
  syncing: boolean;
  message?: string;
  last_error?: string;
  feed_url: string;
  subscribe_url: string;
  packs: FeedPack[];
  new_count: number;
  updated_count: number;
  can_manage: boolean;
}

const KEY = ['hunt-feeds'];

export function useFeedStatus() {
  return useQuery({
    queryKey: KEY,
    queryFn: ({ signal }) => api.get<FeedStatus>('v1/atl/feeds', {}, signal),
    refetchInterval: q => (q.state.data?.syncing ? 2000 : 60000),
  });
}

export type FeedAction = { action: 'sync' } | { action: 'set_key'; key: string } | { action: 'remove_key' };

export function useFeedAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: FeedAction) => api.post<FeedStatus>('v1/atl/feeds', p),
    onSuccess: d => {
      qc.setQueryData(KEY, d);
      // The artifact list changes with the feed.
      qc.invalidateQueries({ queryKey: ['artifact-catalog'] });
      qc.invalidateQueries({ queryKey: ['artifact-search'] });
    },
  });
}

export { FEED_HUNT_TAG, feedHuntRequest, type FeedHuntOptions } from '../pages/feeds/model';
