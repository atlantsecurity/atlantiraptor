// The artifact list on the left of the New hunt dialog: search plus
// filters by platform (Windows, Linux, macOS, cross-platform, cloud),
// cloud service, category and source (built-in, custom, premium feed).
import { useEffect, useMemo, useState } from 'react';
import { Check, Cloud, FilterX, Gem, Search } from 'lucide-react';
import { useArtifactDefinitions, useArtifactSearch } from '../../lib/queries';
import type { ArtifactDescriptor } from '../../lib/types';
import { cn, Input, Select, Spinner, Tooltip } from '../../ui/primitives';
import {
  type ArtifactFacets, type FacetFilter, type Platform, type Source,
  NO_FILTER, OTHER_CATEGORY, PLATFORM_LABELS, facetCounts, facetsOf, isCloudArtifact, isFiltered, matchesFilter,
  needsPrecondition, platformLabel,
} from './artifactFacets';

export type PickerScope = 'hunt' | 'client' | 'server';

export interface CatalogItem { artifact: ArtifactDescriptor; facets: ArtifactFacets }

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

function firstLine(s: string | undefined): string {
  return (s ?? '').trim().split('\n')[0] ?? '';
}

// Every artifact the scope can run that matches the search, with facets.
// A hunt can also pick cloud hunts (Cloud.* server artifacts), which run
// once on the server instead of on the clients.
export function useArtifactCatalog(term: string, scope: PickerScope, enabled: boolean) {
  const client = useArtifactSearch(term, 'CLIENT', enabled && scope !== 'server', 1000);
  const server = useArtifactSearch(term, 'SERVER', enabled && scope !== 'client', 1000);

  const raw = useMemo(() => {
    const out: ArtifactDescriptor[] = [];
    if (scope !== 'server') for (const a of client.data ?? []) out.push({ ...a, type: 'CLIENT' });
    if (scope !== 'client') {
      for (const a of server.data ?? []) {
        if (scope === 'hunt' && !isCloudArtifact(a.name)) continue;
        out.push({ ...a, type: 'SERVER' });
      }
    }
    return out;
  }, [client.data, server.data, scope]);

  // Names like Generic.* or Atlant.Feed.* don't say which OS they run
  // on; their preconditions do.
  const unknown = useMemo(() => raw.filter(a => needsPrecondition(a.name, a.type)).map(a => a.name), [raw]);
  const { data: details } = useArtifactDefinitions(unknown);

  const items: CatalogItem[] = useMemo(() => raw.map(a => {
    const d = details?.get(a.name);
    return { artifact: a, facets: facetsOf({ ...a, precondition: d?.precondition, sources: d?.sources }, !!d) };
  }), [raw, details]);

  return { items, searching: client.isFetching || server.isFetching };
}

const CHIP = 'tw:h-6 tw:px-2 tw:rounded-md tw:text-xs tw:border tw:inline-flex tw:items-center tw:gap-1 tw:whitespace-nowrap';
const chipCls = (on: boolean, disabled = false) => cn(CHIP,
  on ? 'tw:bg-accent-soft tw:border-accent tw:text-accent'
    : disabled ? 'tw:border-line tw:text-faint tw:opacity-60' : 'tw:border-line-strong tw:text-muted tw:hover:bg-hover');

const SOURCE_LABELS: Record<Source, string> = { builtin: 'Built-in', custom: 'Custom', premium: 'Premium feeds' };

export function ArtifactPicker({ scope, selected, onToggle, onCatalog, lockedKind }: {
  scope: PickerScope;
  selected: string[];
  onToggle: (item: CatalogItem) => void;
  onCatalog?: (items: CatalogItem[]) => void;
  // When set, artifacts of the other kind can't join the selection.
  lockedKind?: 'cloud' | 'endpoint';
}) {
  const [search, setSearch] = useState('');
  const term = useDebounced(search.trim(), 150);
  const { items, searching } = useArtifactCatalog(term, scope, true);
  const [filter, setFilter] = useState<FacetFilter>(NO_FILTER);

  useEffect(() => { onCatalog?.(items); }, [items, onCatalog]);

  const all = useMemo(() => items.map(i => i.facets), [items]);
  const counts = useMemo(() => facetCounts(all, filter), [all, filter]);
  const shown = useMemo(() => items.filter(i => matchesFilter(i.facets, filter)), [items, filter]);

  const platforms: Platform[] = scope === 'server'
    ? ['cloud', 'server']
    : scope === 'hunt' ? ['windows', 'linux', 'macos', 'any', 'cloud'] : ['windows', 'linux', 'macos', 'any'];
  const clouds = [...counts.cloud.keys()].sort();
  const categories = [...counts.category.keys()].sort((a, b) =>
    a === OTHER_CATEGORY ? 1 : b === OTHER_CATEGORY ? -1 : a.localeCompare(b));
  const sources = (['builtin', 'custom', 'premium'] as Source[]).filter(s => counts.source.has(s) || filter.source === s);
  const showCloudRow = filter.platform === 'cloud' && clouds.length > 0;

  const set = (patch: Partial<FacetFilter>) => setFilter(f => ({ ...f, ...patch }));
  const pickPlatform = (p: FacetFilter['platform']) => set({
    platform: filter.platform === p ? 'all' : p,
    // A cloud service only means something under Cloud.
    cloud: 'all',
    category: p === 'cloud' ? 'all' : filter.category,
  });

  return (
    <div className="tw:flex tw:flex-col tw:min-h-0 tw:flex-1">
      <div className="tw:p-3 tw:border-b tw:border-line tw:space-y-2.5">
        <div className="tw:relative">
          <Search className="tw:absolute tw:left-2.5 tw:top-1/2 tw:-translate-y-1/2 tw:size-3.5 tw:text-faint" />
          <Input autoFocus value={search} onChange={e => setSearch(e.target.value)}
            placeholder={scope === 'server' ? 'Search server artifacts…' : scope === 'hunt' ? 'Search endpoint and cloud hunts…' : 'Search client artifacts…'}
            className="tw:pl-8" aria-label="Search artifacts" />
          {searching && <Spinner className="tw:absolute tw:right-2.5 tw:top-1/2 tw:-translate-y-1/2 tw:size-3.5" />}
        </div>

        <div className="tw:flex tw:flex-wrap tw:gap-1.5" role="group" aria-label="Platform">
          {platforms.map(p => {
            const n = counts.platform.get(p) ?? 0;
            const on = filter.platform === p;
            return (
              <button key={p} type="button" aria-pressed={on} disabled={!n && !on}
                onClick={() => pickPlatform(p)} className={chipCls(on, !n)}>
                {p === 'cloud' && <Cloud className="tw:size-3" />}
                {p === 'any' ? 'Cross-platform' : PLATFORM_LABELS[p]}
                <span className="tw:text-2xs tw:opacity-70 rx-num">{n}</span>
              </button>
            );
          })}
        </div>

        {showCloudRow && (
          <div className="tw:flex tw:flex-wrap tw:gap-1.5" role="group" aria-label="Cloud service">
            {clouds.map(c => {
              const on = filter.cloud === c;
              return (
                <button key={c} type="button" aria-pressed={on} onClick={() => set({ cloud: on ? 'all' : c })} className={chipCls(on)}>
                  {c}<span className="tw:text-2xs tw:opacity-70 rx-num">{counts.cloud.get(c) ?? 0}</span>
                </button>
              );
            })}
          </div>
        )}

        <div className="tw:flex tw:items-center tw:gap-2">
          {filter.platform !== 'cloud' && categories.length > 1 && (
            <Select value={filter.category} onChange={e => set({ category: e.target.value })}
              className="tw:h-7 tw:text-xs tw:flex-1 tw:min-w-0" aria-label="Category">
              <option value="all">All categories</option>
              {categories.map(c => <option key={c} value={c}>{c} ({counts.category.get(c) ?? 0})</option>)}
            </Select>
          )}
          {sources.length > 1 && (
            <Select value={filter.source} onChange={e => set({ source: e.target.value as FacetFilter['source'] })}
              className="tw:h-7 tw:text-xs tw:flex-1 tw:min-w-0" aria-label="Source">
              <option value="all">All sources</option>
              {sources.map(s => <option key={s} value={s}>{SOURCE_LABELS[s]} ({counts.source.get(s) ?? 0})</option>)}
            </Select>
          )}
        </div>

        <div className="tw:flex tw:items-center tw:text-2xs tw:text-faint">
          <span className="rx-num">{isFiltered(filter) ? `${shown.length} of ${items.length}` : `${items.length}`} artifacts</span>
          {isFiltered(filter) && (
            <button type="button" onClick={() => setFilter(NO_FILTER)}
              className="tw:ml-auto tw:flex tw:items-center tw:gap-1 tw:font-medium tw:text-muted tw:hover:text-fg">
              <FilterX className="tw:size-3" />Clear filters
            </button>
          )}
        </div>
      </div>

      <div className="tw:flex-1 tw:overflow-y-auto">
        {shown.length === 0 && !searching && (
          <div className="tw:p-6 tw:text-center tw:text-xs tw:text-faint">
            {items.length === 0 ? <>No artifacts match “{search}”</> : 'No artifacts match these filters'}
          </div>
        )}
        {shown.map(item => {
          const a = item.artifact;
          const f = item.facets;
          const on = selected.includes(a.name);
          const kind = f.platforms.includes('cloud') ? 'cloud' : 'endpoint';
          const blocked = !on && !!lockedKind && lockedKind !== kind;
          const row = (
            <button key={a.name} type="button" onClick={() => onToggle(item)} aria-pressed={on}
              className={cn('tw:flex tw:w-full tw:items-start tw:gap-2.5 tw:px-3 tw:py-2 tw:text-left tw:border-b tw:border-line/60',
                on ? 'tw:bg-accent-soft' : 'tw:hover:bg-hover', blocked && 'tw:opacity-50')}>
              <span className={cn('tw:mt-0.5 tw:flex tw:size-4 tw:shrink-0 tw:items-center tw:justify-center tw:rounded tw:border',
                on ? 'tw:bg-accent tw:border-accent tw:text-accent-fg' : 'tw:border-line-strong')}>
                {on && <Check className="tw:size-3" />}
              </span>
              <span className="tw:min-w-0 tw:flex-1">
                <span className="tw:block tw:font-mono tw:text-[12px] tw:font-medium tw:break-all">{a.name}</span>
                {a.description && (
                  <span className="tw:block tw:text-2xs tw:text-muted tw:line-clamp-2 tw:mt-0.5">{firstLine(a.description)}</span>
                )}
                <span className="tw:flex tw:flex-wrap tw:gap-1 tw:mt-1">
                  <span className={cn('tw:inline-flex tw:items-center tw:gap-1 tw:px-1.5 tw:rounded tw:text-[10.5px] tw:leading-4',
                    kind === 'cloud' ? 'tw:bg-info-soft tw:text-info' : 'tw:bg-hover tw:text-muted')}>
                    {kind === 'cloud' && <Cloud className="tw:size-2.5" />}{platformLabel(f)}
                  </span>
                  {f.category !== OTHER_CATEGORY && (
                    <span className="tw:px-1.5 tw:rounded tw:text-[10.5px] tw:leading-4 tw:bg-hover tw:text-faint">{f.category}</span>
                  )}
                  {f.source === 'premium' && (
                    <span className="tw:inline-flex tw:items-center tw:gap-1 tw:px-1.5 tw:rounded tw:text-[10.5px] tw:leading-4 tw:bg-accent-soft tw:text-accent">
                      <Gem className="tw:size-2.5" />Premium
                    </span>
                  )}
                  {f.source === 'custom' && (
                    <span className="tw:px-1.5 tw:rounded tw:text-[10.5px] tw:leading-4 tw:bg-warn-soft tw:text-warn">Custom</span>
                  )}
                </span>
              </span>
            </button>
          );
          return blocked
            ? <Tooltip key={a.name} content={kind === 'cloud'
              ? 'Cloud hunts run on the server. Remove the endpoint artifacts to pick one.'
              : 'Endpoint artifacts run on clients. Remove the cloud hunts to pick one.'}>{row}</Tooltip>
            : row;
        })}
      </div>
    </div>
  );
}
