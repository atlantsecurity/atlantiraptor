// Turns a full triage collection into a short list of things worth a
// look, and one activity timeline. Heuristics only: they point the
// analyst at rows to review, they do not decide anything. Pure (no
// React, no network) so they can be unit tested.

export type Row = Record<string, unknown>;

export interface Finding {
  id: string;
  title: string;
  why: string;
  tone: 'bad' | 'warn' | 'info';
  source: string;        // artifact source the rows come from
  rows: Row[];
  summary: (r: Row) => string;
}

export interface TimelineEvent {
  time: number;          // ms since epoch
  what: string;
  detail: string;
  source: string;
}

export const str = (v: unknown): string => (v === undefined || v === null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v));

// Places ordinary users can write to, where malware likes to live.
export const USER_WRITABLE = /([\\/](appdata|temp|tmp|users[\\/]public|programdata|downloads|perflogs)[\\/])|^\/(tmp|var\/tmp|dev\/shm)\//i;

function toMs(v: unknown): number {
  if (typeof v === 'number') return v > 1e17 ? v / 1e6 : v > 1e14 ? v / 1e3 : v > 1e11 ? v : v * 1000;
  const s = str(v);
  if (!s) return 0;
  if (/^\d+(\.\d+)?$/.test(s)) return toMs(Number(s));
  const t = Date.parse(s);
  return Number.isNaN(t) ? 0 : t;
}

export function isPublicIp(ip: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    return true;
  }
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return !(l === '::' || l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('::ffff:127.'));
  }
  return false;
}

export function remoteIp(r: Row): string {
  const raddr = r.Raddr as Record<string, unknown> | undefined;
  if (raddr && typeof raddr === 'object') return str(raddr.IP);
  return str(r.RemoteAddr ?? r.Raddr ?? r.RemoteAddress);
}

function firstMatching(r: Row, cols: string[], re: RegExp): string {
  for (const c of cols) {
    const v = str(r[c]);
    if (v && re.test(v)) return v;
  }
  return '';
}

const base = (s: string) => s.replace(/^.*[\\/]/, '');
// Artifacts with named sources come back as "Artifact/Source"; match on the artifact.
export const artifactOf = (source: string) => source.split('/')[0];
const sourceOf = (sources: Record<string, Row[]>, re: RegExp) => Object.keys(sources).find(s => re.test(s) || re.test(artifactOf(s)));

export function findings(sources: Record<string, Row[]>, now = Date.now()): Finding[] {
  const out: Finding[] = [];

  const ps = sourceOf(sources, /\.(Pslist|Pstree)$/);
  if (ps) {
    const rows = sources[ps];
    const odd = rows.filter(r => USER_WRITABLE.test(str(r.Exe)));
    if (odd.length) out.push({
      id: 'proc-path', source: ps, rows: odd, tone: 'warn',
      title: `${odd.length} process${odd.length === 1 ? '' : 'es'} running from a user-writable folder`,
      why: 'Programs in AppData, Temp, ProgramData or /tmp are a common place for malware.',
      summary: r => `${str(r.Name)} (pid ${str(r.Pid)}) ${str(r.Exe)}`,
    });
    const unsigned = rows.filter(r => {
      const a = r.Authenticode as Record<string, unknown> | undefined;
      const t = str(a && typeof a === 'object' ? a.Trusted : '').toLowerCase();
      return t && t !== 'trusted' && str(r.Exe);
    });
    if (unsigned.length) out.push({
      id: 'proc-unsigned', source: ps, rows: unsigned, tone: 'info',
      title: `${unsigned.length} running program${unsigned.length === 1 ? ' is' : 's are'} not signed by a trusted publisher`,
      why: 'Unsigned is common for in-house tools; review the ones you do not recognise.',
      summary: r => `${str(r.Name)} ${str(r.Exe)}`,
    });
    const deleted = rows.filter(r => r.Deleted === true || /\(deleted\)$/.test(str(r.Exe)));
    if (deleted.length) out.push({
      id: 'proc-deleted', source: ps, rows: deleted, tone: 'bad',
      title: `${deleted.length} process${deleted.length === 1 ? '' : 'es'} running from a deleted file`,
      why: 'A program that deleted its own file on disk is a classic way to hide.',
      summary: r => `${str(r.Name)} (pid ${str(r.Pid)}) ${str(r.Exe)}`,
    });
  }

  // Linux and macOS split connections into TCP4/TCP6/UDP sources.
  const nsAll = Object.keys(sources).filter(s => /\.Netstat$/.test(artifactOf(s)));
  if (nsAll.length) {
    const ns = nsAll.length === 1 ? nsAll[0] : artifactOf(nsAll[0]);
    const ext = nsAll.flatMap(s => sources[s]).filter(r => isPublicIp(remoteIp(r)));
    if (ext.length) out.push({
      id: 'net-external', source: ns, rows: ext, tone: 'info',
      title: `${ext.length} connection${ext.length === 1 ? '' : 's'} to public internet addresses`,
      why: 'Check the processes talking out, especially ones that should not need the internet.',
      summary: r => `${str(r.Name ?? r.Command ?? r.ProcessInfo)} → ${remoteIp(r)}:${str((r.Raddr as Row | undefined)?.Port ?? r.RemotePort)}`,
    });
  }

  const persistence: [RegExp, string, string[]][] = [
    [/\.StartupItems$/, 'autorun', ['OSPath', 'Details', 'Name']],
    [/\.TaskScheduler(\/.*)?$/, 'scheduled task', ['Command', 'Arguments']],
    [/\.Services$/, 'service', ['PathName', 'AbsoluteExePath', 'Command']],
    [/\.(Crontab|LaunchAgents)$/, 'scheduled job', ['Command', 'Program', 'ProgramArguments', 'Data']],
  ];
  for (const [re, what, cols] of persistence) {
    const src = sourceOf(sources, re);
    if (!src) continue;
    const odd = sources[src].filter(r => firstMatching(r, cols, USER_WRITABLE));
    if (odd.length) out.push({
      id: `persist-${what}`, source: src, rows: odd, tone: 'bad',
      title: `${odd.length} ${what}${odd.length === 1 ? '' : 's'} starting a program from a user-writable folder`,
      why: 'Persistence pointing into AppData, Temp, ProgramData or /tmp deserves a look.',
      summary: r => `${str(r.TaskName ?? r.Name ?? r.DisplayName)} ${firstMatching(r, cols, USER_WRITABLE)}`.trim(),
    });
  }

  const pf = sourceOf(sources, /\.Prefetch$/);
  if (pf) {
    const day = now - 24 * 3600 * 1000;
    const recent = sources[pf].filter(r => lastRun(r) >= day);
    const oddRecent = recent.filter(r => USER_WRITABLE.test(str(r.ExecutablePath ?? r.ExecutableDosPath)));
    if (oddRecent.length) out.push({
      id: 'exec-odd', source: pf, rows: oddRecent, tone: 'warn',
      title: `${oddRecent.length} program${oddRecent.length === 1 ? '' : 's'} from user-writable folders ran in the last 24 hours`,
      why: 'From Prefetch: execution evidence even if the file is gone.',
      summary: r => `${str(r.Executable)} ${str(r.ExecutablePath ?? r.ExecutableDosPath)}`,
    });
  }

  return out;
}

function lastRun(r: Row): number {
  const v = r.LastRunTimes;
  if (Array.isArray(v)) return Math.max(0, ...v.map(toMs));
  return toMs(v);
}

/** One merged, newest-first timeline from the triage sources. */
export function timeline(sources: Record<string, Row[]>, limit = 2000): TimelineEvent[] {
  const ev: TimelineEvent[] = [];
  for (const [source, rows] of Object.entries(sources)) {
    const art = artifactOf(source);
    for (const r of rows) {
      if (/\.(Pslist|Pstree)$/.test(art) && r.CreateTime) {
        ev.push({ time: toMs(r.CreateTime), what: 'Process started', detail: `${str(r.Name)} (pid ${str(r.Pid)}) ${str(r.CommandLine || r.Exe)}`, source });
      } else if (/\.Prefetch$/.test(art)) {
        const times = Array.isArray(r.LastRunTimes) ? r.LastRunTimes : [r.LastRunTimes];
        for (const t of times) if (t) ev.push({ time: toMs(t), what: 'Program ran', detail: str(r.ExecutablePath || r.Executable), source });
      } else if (/\.(LastUserLogin)$/.test(art)) {
        ev.push({ time: toMs(r.login_Time ?? r.Time ?? r.time), what: 'Logon', detail: `${str(r.login_User ?? r.User)} from ${str(r.login_Host ?? r.Host)}`, source });
      } else if (/\.TaskScheduler/.test(source) && r.RegistrationTime) {
        ev.push({ time: toMs(r.RegistrationTime), what: 'Task registered', detail: `${str(r.TaskName ?? base(str(r.OSPath)))} ${str(r.Command)}`, source });
      } else if (/\.Bam$/.test(art) && (r.Time ?? r.LastRun)) {
        ev.push({ time: toMs(r.Time ?? r.LastRun), what: 'Program ran (BAM)', detail: str(r.Binary ?? r.Program ?? r.Path), source });
      }
    }
  }
  return ev.filter(e => e.time > 0).sort((a, b) => b.time - a.time).slice(0, limit);
}
