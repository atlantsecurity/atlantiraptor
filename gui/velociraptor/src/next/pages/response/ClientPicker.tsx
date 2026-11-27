// Search for clients by hostname, client ID or label and select one or
// more. Selected clients show as chips.
import { useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Plus, Search, X } from 'lucide-react';
import * as api from '../../lib/api';
import type { SearchClientsResponse } from '../../lib/types';
import { cn, Input } from '../../ui/primitives';

export const MAX_PICKED_CLIENTS = 100;

export interface PickedClient { id: string; hostname: string; online?: boolean }

const ONLINE_MS = 15 * 60 * 1000;

function searchQuery(q: string): string {
  const t = q.trim();
  if (!t) return '';
  // Pass search syntax (label:x, host:y) and wildcards through; otherwise
  // match hostnames and client IDs by prefix.
  return t.includes(':') || t.includes('*') ? t : `${t}*`;
}

function useClientMatches(q: string) {
  const query = searchQuery(q);
  return useQuery({
    queryKey: ['client-picker', query],
    enabled: query.length > 0,
    queryFn: ({ signal }) => api.get<SearchClientsResponse>('v1/SearchClients', { query, limit: 25, name_only: false }, signal),
    select: d => ({
      total: Number(d.total ?? 0),
      items: (d.items ?? []).map(c => ({
        id: c.client_id,
        hostname: c.os_info?.hostname || c.os_info?.fqdn || c.client_id,
        online: Date.now() - Number(c.last_seen_at ?? 0) / 1000 < ONLINE_MS,
        labels: c.labels ?? [],
      })),
    }),
    staleTime: 5_000,
    placeholderData: keepPreviousData,
  });
}

interface Props { value: PickedClient[]; onChange: (v: PickedClient[]) => void }

export function ClientPicker({ value, onChange }: Props) {
  const [q, setQ] = useState('');
  const { data, isFetching } = useClientMatches(q);
  const picked = new Set(value.map(c => c.id));
  const add = (cs: PickedClient[]) => {
    const next = [...value];
    for (const c of cs) {
      if (!picked.has(c.id) && next.length < MAX_PICKED_CLIENTS) next.push(c);
    }
    onChange(next);
  };
  const remove = (id: string) => onChange(value.filter(c => c.id !== id));
  const unpicked = (data?.items ?? []).filter(c => !picked.has(c.id));

  return (
    <div className="tw:space-y-2">
      {value.length > 0 && (
        <div className="tw:flex tw:flex-wrap tw:gap-1.5">
          {value.map(c => (
            <span key={c.id} className="tw:inline-flex tw:items-center tw:gap-1 tw:rounded-md tw:border tw:border-accent tw:bg-accent-soft tw:px-2 tw:py-0.5 tw:text-xs">
              <span className="tw:font-medium">{c.hostname}</span>
              <span className="tw:font-mono tw:text-[10px] tw:text-faint">{c.id}</span>
              <button type="button" aria-label={`Remove ${c.hostname}`} className="tw:text-muted tw:hover:text-fg" onClick={() => remove(c.id)}>
                <X className="tw:size-3" />
              </button>
            </span>
          ))}
          <button type="button" className="tw:text-2xs tw:text-muted tw:hover:text-fg tw:underline" onClick={() => onChange([])}>Clear</button>
        </div>
      )}
      <div className="tw:relative">
        <Search className="tw:absolute tw:left-2 tw:top-2 tw:size-4 tw:text-faint" />
        <Input value={q} onChange={e => setQ(e.target.value)} className="tw:pl-8"
          placeholder="Search hostname or client ID, or label:name" />
      </div>
      {q.trim() && (
        <div className="tw:rounded-md tw:border tw:border-line tw:max-h-64 tw:overflow-y-auto">
          {unpicked.length === 0 && (
            <div className="tw:px-3 tw:py-2 tw:text-xs tw:text-muted">{isFetching ? 'Searching…' : 'No other matching clients.'}</div>
          )}
          {unpicked.map(c => (
            <button key={c.id} type="button" onClick={() => add([c])} disabled={value.length >= MAX_PICKED_CLIENTS}
              className="tw:flex tw:w-full tw:items-center tw:gap-2 tw:px-3 tw:py-1.5 tw:text-left tw:text-xs tw:hover:bg-hover tw:disabled:opacity-50">
              <span className={cn('tw:size-2 tw:rounded-full', c.online ? 'tw:bg-ok' : 'tw:bg-line-strong')} title={c.online ? 'Online' : 'Offline'} />
              <span className="tw:font-medium">{c.hostname}</span>
              <span className="tw:font-mono tw:text-[10px] tw:text-faint">{c.id}</span>
              {c.labels.length > 0 && <span className="tw:text-faint tw:truncate">{c.labels.join(', ')}</span>}
              <Plus className="tw:ml-auto tw:size-3.5 tw:text-muted" />
            </button>
          ))}
          {unpicked.length > 1 && (
            <button type="button" onClick={() => add(unpicked)} disabled={value.length >= MAX_PICKED_CLIENTS}
              className="tw:w-full tw:border-t tw:border-line tw:px-3 tw:py-1.5 tw:text-left tw:text-xs tw:text-accent tw:hover:bg-hover">
              Add all {unpicked.length} shown{data && data.total > unpicked.length + value.length ? ` (of ${data.total} matches)` : ''}
            </button>
          )}
        </div>
      )}
      {value.length >= MAX_PICKED_CLIENTS && (
        <div className="tw:text-2xs tw:text-warn">At most {MAX_PICKED_CLIENTS} clients. For more, use a label or OS target.</div>
      )}
    </div>
  );
}
