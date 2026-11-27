// Full triage: the standard first-look collection for one host, run as a
// single urgent flow. Used by the host page and by alerts.
import * as api from './api';
import { runArtifacts } from './queries';
import type { ApiClient, GetArtifactsResponse } from './types';

export type OS = 'windows' | 'linux' | 'darwin' | 'other';

export const osOf = (c?: ApiClient): OS => {
  const s = (c?.os_info?.system ?? '').toLowerCase();
  return s === 'windows' ? 'windows' : s === 'linux' ? 'linux' : s === 'darwin' || s === 'macos' ? 'darwin' : 'other';
};

export const FULL_TRIAGE: Record<OS, string[]> = {
  windows: [
    'Windows.System.Pslist', 'Windows.Network.Netstat', 'Windows.Sys.StartupItems',
    'Windows.System.TaskScheduler', 'Windows.System.Services', 'Windows.Sys.Users',
    'Windows.Forensics.Prefetch', 'Windows.Forensics.Amcache', 'Windows.Registry.AppCompatCache',
    'Windows.Forensics.Bam', 'Windows.Registry.UserAssist',
  ],
  linux: [
    'Linux.Sys.Pslist', 'Linux.Network.Netstat', 'Linux.Sys.Users', 'Linux.Sys.LastUserLogin',
    'Linux.Sys.Crontab', 'Linux.Ssh.AuthorizedKeys', 'Linux.Sys.BashHistory',
  ],
  darwin: [
    'Generic.System.Pstree', 'MacOS.Network.Netstat', 'MacOS.Sys.Users',
    'MacOS.System.LaunchAgents', 'MacOS.Sys.BashHistory',
  ],
  other: ['Generic.System.Pstree'],
};

/** Marks a flow as a full triage so the host page can find it again. */
export const TRIAGE_USER_DATA = 'atl-full-triage';

/** The triage artifacts for this OS that exist on this server. */
export async function availableTriage(os: OS): Promise<string[]> {
  const names = FULL_TRIAGE[os];
  const r = await api.post<GetArtifactsResponse>('v1/GetArtifacts', {
    names, number_of_results: names.length, fields: { name: true },
  });
  const have = new Set((r.items ?? []).map(a => a.name));
  return names.filter(n => have.has(n));
}

/** Starts a full triage on a host and returns the flow id. */
export async function startFullTriage(clientId: string, client?: ApiClient): Promise<string> {
  const c = client ?? await api.get<ApiClient>(`v1/GetClient/${clientId}`, {});
  const arts = await availableTriage(osOf(c));
  if (!arts.length) throw new Error('None of the triage artifacts are installed on this server.');
  const r = await runArtifacts(clientId, arts, {}, true, TRIAGE_USER_DATA);
  if (!r.flow_id) throw new Error('The triage collection was not started.');
  return r.flow_id;
}
