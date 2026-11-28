// A readable summary of a full triage collection: what each area
// returned, what was flagged, and indicators of compromise pulled out of
// the rows by fixed rules (no AI). Also builds the compact text the
// existing AI triage sends, so the model sees the flagged rows rather
// than thousands of raw ones. Pure, so it can be unit tested.
import { USER_WRITABLE, artifactOf, isPublicIp, remoteIp, str, type Finding, type Row } from './findings.ts';

export interface Area {
  id: string;
  label: string;
  sources: { name: string; rows: number }[];
  rows: number;
  flagged: number;        // rows named by a finding in this area
  findings: Finding[];
}

const AREAS: { id: string; label: string; re: RegExp }[] = [
  { id: 'processes', label: 'Processes', re: /\.(Pslist|Pstree)$/ },
  { id: 'network', label: 'Network connections', re: /\.Netstat$/ },
  { id: 'persistence', label: 'Persistence', re: /\.(StartupItems|TaskScheduler(\/.*)?|Services|Crontab|LaunchAgents|AuthorizedKeys)$/ },
  { id: 'users', label: 'Users and logons', re: /\.(Users|LastUserLogin)$/ },
  { id: 'execution', label: 'Execution history', re: /\.(Prefetch|Amcache|AppCompatCache|Bam|UserAssist)$/ },
  { id: 'shell', label: 'Shell history', re: /\.BashHistory$/ },
];

const areaOf = (source: string) => AREAS.find(a => a.re.test(source) || a.re.test(artifactOf(source))) ?? { id: 'other', label: 'Other', re: /./ };

export function areas(sources: Record<string, Row[]>, found: Finding[]): Area[] {
  const out = new Map<string, Area>();
  for (const [name, rows] of Object.entries(sources)) {
    const def = areaOf(name);
    const a = out.get(def.id) ?? { id: def.id, label: def.label, sources: [], rows: 0, flagged: 0, findings: [] };
    a.sources.push({ name, rows: rows.length });
    a.rows += rows.length;
    out.set(def.id, a);
  }
  for (const f of found) {
    const a = out.get(areaOf(f.source).id);
    if (!a) continue;
    a.findings.push(f);
    a.flagged += f.rows.length;
  }
  const order = [...AREAS.map(a => a.id), 'other'];
  return [...out.values()].sort((x, y) => order.indexOf(x.id) - order.indexOf(y.id));
}

export type IocKind = 'ip' | 'domain' | 'url' | 'sha256' | 'sha1' | 'md5' | 'path' | 'command';

export interface FoundIoc {
  kind: IocKind;
  value: string;
  source: string;     // artifact source it was seen in
  context: string;    // e.g. the process or task it belongs to
  count: number;
}

export const IOC_LABELS: Record<IocKind, string> = {
  ip: 'IP address', domain: 'Domain', url: 'URL', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5',
  path: 'Suspicious path', command: 'Suspicious command',
};

const MAX_IOCS = 500;

// Command lines that are almost never benign. Each one is a known
// download-and-run, encoded or reverse-shell pattern.
export const SUSPICIOUS_COMMANDS: [RegExp, string][] = [
  [/powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i, 'Encoded PowerShell'],
  [/\b(iex|invoke-expression)\b.*\b(downloadstring|downloadfile|invoke-webrequest|iwr|net\.webclient)\b|\b(downloadstring|net\.webclient)\b.*\b(iex|invoke-expression)\b/i, 'PowerShell download and run'],
  [/frombase64string\(/i, 'Base64-decoded script'],
  [/certutil(\.exe)?\b.*-(urlcache|decode)\b/i, 'certutil download or decode'],
  [/mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)/i, 'mshta running remote or inline script'],
  [/rundll32(\.exe)?\b.*javascript:/i, 'rundll32 running script'],
  [/regsvr32(\.exe)?\b.*\/i:\s*https?:/i, 'regsvr32 loading a remote scriptlet'],
  [/bitsadmin(\.exe)?\b.*\/transfer\b/i, 'bitsadmin download'],
  [/\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, 'Download piped to a shell'],
  [/base64\s+(-d|--decode)\b[^|;]*\|\s*(ba|z|da)?sh\b/i, 'Base64 piped to a shell'],
  [/\/dev\/tcp\/\d|\bnc(at)?\b.*\s-e\s|\bsocat\b.*\bexec:/i, 'Reverse shell'],
];

// Columns that hold a command line or something run.
const COMMAND_COLS = ['CommandLine', 'Command', 'Arguments', 'PathName', 'Details', 'Data', 'Program', 'ProgramArguments', 'Line', 'ImagePath'];
const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>`|\\]{3,300}/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const PATH_RE = /(?:[a-z]:\\|\/)[^"'<>|\r\n]*?\.(?:exe|dll|scr|ps1|bat|cmd|vbs|js|hta|jar|sh|py|elf|bin)\b/gi;

function hashKind(v: string): IocKind | null {
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  return null;
}

/** Every hash in a row, including nested ones such as Pslist's Hash.SHA256. */
function hashesIn(r: Row, out: [IocKind, string][], depth = 0) {
  for (const [k, v] of Object.entries(r)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < 2) {
      hashesIn(v as Row, out, depth + 1);
    } else if (typeof v === 'string' && /sha|md5|hash/i.test(k)) {
      // Amcache stores SHA-1 as "0000" + 40 hex digits.
      const s = v.length === 44 && v.startsWith('0000') ? v.slice(4) : v;
      const kind = hashKind(s);
      if (kind) out.push([kind, s.toLowerCase()]);
    }
  }
}

const contextOf = (r: Row) => str(r.Name ?? r.TaskName ?? r.DisplayName ?? r.Executable ?? r.User ?? r.Command ?? '').slice(0, 120);

export function extractIocs(sources: Record<string, Row[]>, found: Finding[]): FoundIoc[] {
  const map = new Map<string, FoundIoc>();
  const add = (kind: IocKind, value: string, source: string, context: string) => {
    const v = value.trim();
    if (!v) return;
    const key = `${kind}|${kind === 'path' || kind === 'command' ? v : v.toLowerCase()}`;
    const have = map.get(key);
    if (have) { have.count++; return; }
    if (map.size >= MAX_IOCS) return;
    map.set(key, { kind, value: kind === 'path' || kind === 'command' || kind === 'url' ? v : v.toLowerCase(), source, context, count: 1 });
  };

  for (const [source, rows] of Object.entries(sources)) {
    const isNet = /\.Netstat$/.test(artifactOf(source));
    for (const r of rows) {
      if (isNet) {
        const ip = remoteIp(r);
        if (isPublicIp(ip)) add('ip', ip, source, str(r.Name ?? r.Command ?? ''));
      }
      // One string per row, so a program and its arguments in separate
      // columns (scheduled tasks) are checked together.
      const text = COMMAND_COLS.map(c => str(r[c])).filter(Boolean).join(' ');
      if (text) {
        for (const [re, what] of SUSPICIOUS_COMMANDS) {
          if (re.test(text)) { add('command', text.slice(0, 500), source, `${what}${contextOf(r) ? ` · ${contextOf(r)}` : ''}`); break; }
        }
        for (const m of text.match(URL_RE) ?? []) {
          const url = m.replace(/[),.;\]]+$/, '');
          add('url', url, source, contextOf(r));
          try {
            const host = new URL(url).hostname;
            if (host && !/^[\d.]+$/.test(host) && host.includes('.')) add('domain', host, source, contextOf(r));
            else if (isPublicIp(host)) add('ip', host, source, contextOf(r));
          } catch { /* not a URL after all */ }
        }
        for (const ip of text.match(IPV4_RE) ?? []) if (isPublicIp(ip)) add('ip', ip, source, contextOf(r));
      }
    }
  }

  // Paths and hashes only for rows already flagged (and Amcache entries
  // from user-writable folders): every program on the host would bury
  // the few that matter.
  const flagged: [string, Row][] = found.flatMap(f => f.rows.map(r => [f.source, r] as [string, Row]));
  for (const [source, rows] of Object.entries(sources)) {
    if (/\.Amcache$/.test(artifactOf(source))) for (const r of rows) if (USER_WRITABLE.test(str(r.FullPath))) flagged.push([source, r]);
  }
  for (const [source, r] of flagged) {
    // Executables without an extension (Linux) are whole column values.
    for (const c of ['Exe', 'FullPath', 'ExecutablePath', 'OSPath', 'PathName']) {
      const v = str(r[c]).replace(/ \(deleted\)$/, '');
      if (/^([a-z]:\\|\/)\S+$/i.test(v) && USER_WRITABLE.test(v)) add('path', v, source, contextOf(r));
    }
    for (const v of Object.values(r)) {
      if (typeof v !== 'string') continue;
      for (const p of v.match(PATH_RE) ?? []) if (USER_WRITABLE.test(p)) add('path', p, source, contextOf(r));
    }
    const hashes: [IocKind, string][] = [];
    hashesIn(r, hashes);
    for (const [kind, h] of hashes) add(kind, h, source, contextOf(r));
  }

  const order: IocKind[] = ['command', 'ip', 'domain', 'url', 'path', 'sha256', 'sha1', 'md5'];
  return [...map.values()].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || b.count - a.count);
}

/** Indicators in the format IOC sweep accepts ("type,value"). */
export function iocSweepText(iocs: FoundIoc[]): string {
  const type: Partial<Record<IocKind, string>> = { ip: 'ip', domain: 'domain', sha256: 'sha256', sha1: 'sha1', md5: 'md5', path: 'path' };
  return iocs.filter(i => type[i.kind]).map(i => `${type[i.kind]},${i.value}`).join('\n');
}

export function headline(found: Finding[], iocs: FoundIoc[]): { tone: 'bad' | 'warn' | 'ok'; text: string } {
  const bad = found.filter(f => f.tone === 'bad').length;
  const warn = found.filter(f => f.tone === 'warn').length;
  const cmds = iocs.filter(i => i.kind === 'command').length;
  const parts: string[] = [];
  if (bad + cmds) parts.push(`${bad + cmds} thing${bad + cmds === 1 ? '' : 's'} to review`);
  if (warn) parts.push(`${warn} to check`);
  if (!parts.length) return { tone: 'ok', text: 'Nothing flagged by the built-in checks.' };
  return { tone: bad + cmds ? 'bad' : 'warn', text: `${parts.join(', ')}.` };
}

/**
 * The text the AI triage sends: per-area counts, each finding with its
 * rows, and the indicators. Far smaller than the raw collection, and the
 * caller still caps it.
 */
export function aiContext(host: string, clientId: string, flowId: string,
  sources: Record<string, Row[]>, found: Finding[], iocs: FoundIoc[]): string {
  const lines: string[] = [`Host: ${host} (${clientId})`, `Full triage collection: ${flowId}`, '', '## Rows returned per artifact'];
  for (const [s, rows] of Object.entries(sources)) lines.push(`${s}: ${rows.length}`);
  lines.push('', '## Findings from built-in checks');
  if (!found.length) lines.push('None.');
  for (const f of found) {
    lines.push(`### [${f.tone === 'bad' ? 'review' : f.tone === 'warn' ? 'check' : 'note'}] ${f.title} (${f.source})`);
    for (const r of f.rows.slice(0, 15)) lines.push(JSON.stringify(r));
    if (f.rows.length > 15) lines.push(`…and ${f.rows.length - 15} more rows`);
  }
  lines.push('', '## Indicators extracted by rules');
  if (!iocs.length) lines.push('None.');
  for (const i of iocs.slice(0, 200)) lines.push(`${i.kind}\t${i.value}\t${i.context}\t(${i.source}, seen ${i.count}x)`);
  // Command lines of every process, so the model can spot what the rules missed.
  const ps = Object.keys(sources).find(s => /\.(Pslist|Pstree)$/.test(artifactOf(s)));
  if (ps) {
    lines.push('', `## Process command lines (${ps})`);
    for (const r of sources[ps].slice(0, 400)) {
      const cmd = str(r.CommandLine || r.Exe);
      if (cmd) lines.push(`${str(r.Pid)}\t${str(r.Name)}\t${cmd.slice(0, 300)}`);
    }
  }
  return lines.join('\n');
}

export const AI_TASK = 'Triage this full triage summary of one host. Say whether it looks compromised and why, '
  + 'then list every indicator of compromise you see (IP addresses, domains, URLs, hashes, file paths, persistence entries, '
  + 'suspicious commands) with the evidence for each, and the next steps.';
