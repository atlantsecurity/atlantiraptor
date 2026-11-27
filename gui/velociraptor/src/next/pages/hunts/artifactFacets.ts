// Facets for the artifact picker in the New hunt dialog: which
// platform an artifact runs on, which cloud service it hunts, what kind
// of artifact it is and where it came from. Everything is derived from
// the artifact name (and its precondition when the name does not say),
// so new artifacts, feed packs and cloud providers are picked up without
// code changes.

export type Platform = 'windows' | 'linux' | 'macos' | 'any' | 'cloud' | 'server';
export type Source = 'builtin' | 'custom' | 'premium';

export interface ArtifactFacets {
  name: string;
  // The operating systems the artifact runs on. 'any' means every
  // client OS; cloud and server artifacts run on the server.
  platforms: Platform[];
  cloud?: string;
  category: string;
  source: Source;
}

export const PLATFORM_LABELS: Record<Platform, string> = {
  windows: 'Windows', linux: 'Linux', macos: 'macOS', any: 'Any OS', cloud: 'Cloud', server: 'Server',
};

const OS_SEGMENTS: Record<string, Platform> = {
  windows: 'windows', linux: 'linux', macos: 'macos', osx: 'macos', darwin: 'macos', generic: 'any',
};

// Cloud.<Provider>.* -> display name. Providers not listed here show
// their name segment as is.
const CLOUD_PROVIDERS: Record<string, string> = {
  m365: 'Microsoft 365', microsoft365: 'Microsoft 365', o365: 'Microsoft 365', office365: 'Microsoft 365',
  entra: 'Microsoft 365', entraid: 'Microsoft 365',
  googleworkspace: 'Google Workspace', gworkspace: 'Google Workspace', gws: 'Google Workspace', workspace: 'Google Workspace',
  okta: 'Okta', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', googlecloud: 'Google Cloud',
  github: 'GitHub', slack: 'Slack', salesforce: 'Salesforce', box: 'Box', dropbox: 'Dropbox', zoom: 'Zoom',
};

// The name segment after the platform (Windows.EventLogs.X) grouped into
// a short list of categories. Unknown segments fall into Other.
const CATEGORY_SEGMENTS: Record<string, string> = {
  detection: 'Detection', attack: 'Detection', sigma: 'Detection', yara: 'Detection', persistence: 'Detection',
  forensics: 'Forensics', forensic: 'Forensics', ntfs: 'Forensics', carving: 'Forensics', timeline: 'Forensics', analysis: 'Forensics',
  eventlogs: 'Event logs', etw: 'Event logs', syslog: 'Event logs', logs: 'Event logs', events: 'Event logs',
  registry: 'Registry',
  network: 'Network', ssh: 'Network',
  memory: 'Memory and processes', proc: 'Memory and processes', processes: 'Memory and processes',
  sys: 'System', system: 'System', users: 'System', mounts: 'System', debian: 'System', rhel: 'System',
  suse: 'System', activedirectory: 'System', client: 'System',
  applications: 'Applications',
  search: 'File search',
  triage: 'Triage', kapefiles: 'Triage', collectors: 'Triage', collection: 'Triage', packs: 'Triage',
  remediation: 'Remediation',
  osquery: 'Tools', sysinternals: 'Tools', utils: 'Tools',
};

export const OTHER_CATEGORY = 'Other';

const PREMIUM_PREFIX = 'Atlant.Feed.';

export function isCloudArtifact(name: string): boolean {
  return /^Cloud\.[^.]+\./.test(name);
}

export function cloudProvider(name: string): string | undefined {
  const m = /^Cloud\.([^.]+)\./.exec(name);
  if (!m) return undefined;
  return CLOUD_PROVIDERS[m[1].toLowerCase()] ?? m[1];
}

// Strips the wrappers that put an artifact under another namespace
// (Custom.Windows.X, Atlant.Feed.Linux.X, Exchange.MacOS.X) so the
// platform segment comes first.
function nameSegments(name: string): string[] {
  let n = name;
  if (n.startsWith(PREMIUM_PREFIX)) n = n.slice(PREMIUM_PREFIX.length);
  n = n.replace(/^(Custom|Exchange)\./, '');
  return n.split('.');
}

// The platform a name declares, if any.
export function namePlatform(name: string): Platform | undefined {
  if (isCloudArtifact(name)) return 'cloud';
  return OS_SEGMENTS[nameSegments(name)[0]?.toLowerCase() ?? ''];
}

// Reads the operating systems out of VQL preconditions such as
// `SELECT OS From info() where OS = 'windows'`. No OS named means the
// artifact runs everywhere.
export function preconditionPlatforms(preconditions: (string | undefined)[]): Platform[] {
  const text = preconditions.filter(Boolean).join('\n').toLowerCase();
  const out: Platform[] = [];
  if (/\bwindows\b/.test(text)) out.push('windows');
  if (/\blinux\b/.test(text)) out.push('linux');
  if (/\b(darwin|macos|osx)\b/.test(text)) out.push('macos');
  return out.length ? out : ['any'];
}

export function categoryOf(name: string): string {
  if (isCloudArtifact(name)) return OTHER_CATEGORY;
  const segs = nameSegments(name);
  // Skip the platform segment when there is one.
  const seg = OS_SEGMENTS[segs[0]?.toLowerCase() ?? ''] ? segs[1] : segs[0];
  return CATEGORY_SEGMENTS[seg?.toLowerCase() ?? ''] ?? OTHER_CATEGORY;
}

export function sourceOf(name: string, builtIn?: boolean): Source {
  if (name.startsWith(PREMIUM_PREFIX)) return 'premium';
  return builtIn ? 'builtin' : 'custom';
}

// Whether the artifact's platform needs its precondition to be known:
// the name does not name exactly one OS.
export function needsPrecondition(name: string, type?: string): boolean {
  if ((type ?? '').toUpperCase().startsWith('SERVER')) return false;
  const p = namePlatform(name);
  return p === undefined || p === 'any';
}

export function facetsOf(a: {
  name: string; built_in?: boolean; type?: string;
  precondition?: string; sources?: { precondition?: string }[];
}, detailsKnown = false): ArtifactFacets {
  const server = (a.type ?? '').toUpperCase().startsWith('SERVER');
  let platforms: Platform[];
  const fromName = namePlatform(a.name);
  if (fromName === 'cloud') platforms = ['cloud'];
  else if (server) platforms = ['server'];
  else if (fromName && fromName !== 'any') platforms = [fromName];
  else if (detailsKnown) platforms = preconditionPlatforms([a.precondition, ...(a.sources ?? []).map(s => s.precondition)]);
  else platforms = ['any'];
  return {
    name: a.name,
    platforms,
    cloud: cloudProvider(a.name),
    category: categoryOf(a.name),
    source: sourceOf(a.name, a.built_in),
  };
}

export interface FacetFilter {
  platform: Platform | 'all';
  cloud: string | 'all';
  category: string | 'all';
  source: Source | 'all';
}

export const NO_FILTER: FacetFilter = { platform: 'all', cloud: 'all', category: 'all', source: 'all' };

// An OS filter keeps the artifacts that run on that OS, cross-platform
// ones included.
export function matchesPlatform(f: ArtifactFacets, p: FacetFilter['platform']): boolean {
  if (p === 'all') return true;
  if (p === 'windows' || p === 'linux' || p === 'macos') {
    return f.platforms.includes(p) || f.platforms.includes('any');
  }
  return f.platforms.includes(p);
}

export function matchesFilter(f: ArtifactFacets, filter: FacetFilter, ignore?: keyof FacetFilter): boolean {
  if (ignore !== 'platform' && !matchesPlatform(f, filter.platform)) return false;
  if (ignore !== 'cloud' && filter.cloud !== 'all' && f.cloud !== filter.cloud) return false;
  if (ignore !== 'category' && filter.category !== 'all' && f.category !== filter.category) return false;
  if (ignore !== 'source' && filter.source !== 'all' && f.source !== filter.source) return false;
  return true;
}

export function isFiltered(filter: FacetFilter): boolean {
  return filter.platform !== 'all' || filter.cloud !== 'all' || filter.category !== 'all' || filter.source !== 'all';
}

// Counts per facet value. Each facet is counted with the other filters
// applied, so a count says how many results picking that value gives.
export function facetCounts(all: ArtifactFacets[], filter: FacetFilter) {
  const platform = new Map<Platform | 'all', number>();
  const cloud = new Map<string, number>();
  const category = new Map<string, number>();
  const source = new Map<Source, number>();
  const bump = <K,>(m: Map<K, number>, k: K) => m.set(k, (m.get(k) ?? 0) + 1);
  const PLATFORMS: Platform[] = ['windows', 'linux', 'macos', 'any', 'cloud', 'server'];
  for (const f of all) {
    if (matchesFilter(f, filter, 'platform')) {
      bump(platform, 'all');
      for (const p of PLATFORMS) if (matchesPlatform(f, p)) bump(platform, p);
    }
    if (f.cloud && matchesFilter(f, filter, 'cloud')) bump(cloud, f.cloud);
    if (matchesFilter(f, filter, 'category')) bump(category, f.category);
    if (matchesFilter(f, filter, 'source')) bump(source, f.source);
  }
  return { platform, cloud, category, source };
}

// The one client OS every selected artifact is limited to, if there is
// one, so the dialog can offer to target only those clients.
export function commonOs(selected: (ArtifactFacets | undefined)[]): 'windows' | 'linux' | 'macos' | undefined {
  let os: Platform | undefined;
  for (const f of selected) {
    if (!f || f.platforms.length !== 1) return undefined;
    const p = f.platforms[0];
    if (p !== 'windows' && p !== 'linux' && p !== 'macos') return undefined;
    if (os && os !== p) return undefined;
    os = p;
  }
  return os as 'windows' | 'linux' | 'macos' | undefined;
}

export function platformLabel(f: ArtifactFacets): string {
  if (f.cloud) return f.cloud;
  return f.platforms.map(p => PLATFORM_LABELS[p]).join(' · ');
}
