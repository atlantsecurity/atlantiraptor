// Catalog of fleet response actions. Each action runs one or more
// artifacts as a hunt; per-OS artifacts carry their own preconditions, so a
// single hunt can target a mixed fleet and every client runs only the
// artifact that fits it.
import React from 'react';
import {
  Ban, CalendarX, FileX2, PackageX, ShieldAlert, ShieldCheck, Skull, Undo2, UserCheck, UserX, Wrench,
} from 'lucide-react';

export type ResponseGroup = 'Containment' | 'Process' | 'File' | 'Persistence' | 'Accounts' | 'Agent';
export const GROUPS: ResponseGroup[] = ['Containment', 'Process', 'File', 'Persistence', 'Accounts', 'Agent'];

export interface ActionField {
  key: string;
  label: string;
  kind: 'text' | 'textarea';
  placeholder?: string;
  help?: string;
  required?: boolean;
  mono?: boolean;
  initial?: string;
}

export interface ResponseAction {
  id: string;
  group: ResponseGroup;
  title: string;
  description: string;
  icon: React.ReactNode;
  platforms: string;
  artifacts: string[];
  // Parameters sent to every artifact of the action, regardless of input.
  fixed: Record<string, string>;
  fields: ActionField[];
  // When set, the action can run as a dry run that only lists matches.
  // The value is the parameter that arms the real action.
  armParam?: string;
  // Short text for hunt descriptions, built from the field values.
  summary: (v: Record<string, string>) => string;
}

const QUARANTINE = ['Windows.Remediation.Quarantine', 'Linux.Remediation.Quarantine', 'MacOS.Remediation.Quarantine'];

export const ACTIONS: ResponseAction[] = [
  {
    id: 'quarantine', group: 'Containment', title: 'Network quarantine', icon: <ShieldAlert />, platforms: 'Windows, Linux, macOS',
    description: 'Cut hosts off from the network except for this server, so you can keep investigating.',
    artifacts: QUARANTINE, fixed: {},
    fields: [{ key: 'MessageBox', label: 'Message shown to the user (optional)', kind: 'textarea', placeholder: 'This computer has been isolated by the security team.' }],
    summary: () => 'Network quarantine',
  },
  {
    id: 'unquarantine', group: 'Containment', title: 'Lift quarantine', icon: <ShieldCheck />, platforms: 'Windows, Linux, macOS',
    description: 'Remove the quarantine firewall policy and restore normal network access.',
    artifacts: QUARANTINE, fixed: { RemovePolicy: 'Y' }, fields: [],
    summary: () => 'Lift quarantine',
  },
  {
    id: 'sinkhole', group: 'Containment', title: 'DNS sinkhole', icon: <Ban />, platforms: 'Windows',
    description: 'Point malicious domains at a sinkhole address via the hosts file. The original file is backed up.',
    artifacts: ['Windows.Remediation.Sinkhole'], fixed: {},
    fields: [{
      key: 'SinkholeTable', label: 'Domains to sinkhole (CSV)', kind: 'textarea', mono: true, required: true,
      initial: 'Domain,Sinkhole,Description\nevil.example,127.0.0.1,C2 domain\n',
      help: 'One row per domain: Domain,Sinkhole,Description',
    }],
    summary: v => `DNS sinkhole (${(v.SinkholeTable ?? '').trim().split('\n').length - 1} domains)`,
  },
  {
    id: 'unsinkhole', group: 'Containment', title: 'Restore hosts file', icon: <Undo2 />, platforms: 'Windows',
    description: 'Undo a DNS sinkhole by restoring the hosts file from its backup.',
    artifacts: ['Windows.Remediation.Sinkhole'], fixed: { RestoreBackup: 'Y' }, fields: [],
    summary: () => 'Restore hosts file',
  },
  {
    id: 'kill', group: 'Process', title: 'Kill process', icon: <Skull />, platforms: 'Windows, Linux, macOS',
    description: 'Terminate processes whose name or path matches a regex. The agent itself is never killed.',
    artifacts: ['Generic.Remediation.KillProcess'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [
      { key: 'ProcessRegex', label: 'Process name or path (regex)', kind: 'text', mono: true, required: true, placeholder: '(?i)^evil\\.exe$' },
      { key: 'CommandLineRegex', label: 'Command line (regex, optional)', kind: 'text', mono: true, placeholder: '.' },
    ],
    summary: v => `Kill process ${v.ProcessRegex}`,
  },
  {
    id: 'delete', group: 'File', title: 'Delete file', icon: <FileX2 />, platforms: 'Windows, Linux, macOS',
    description: 'Delete files matching a glob, optionally only with a given SHA256. Hosts with too many matches are skipped.',
    artifacts: ['Generic.Remediation.DeleteFile'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [
      { key: 'Glob', label: 'File glob', kind: 'text', mono: true, required: true, placeholder: 'C:/Users/*/AppData/Local/Temp/evil.exe' },
      { key: 'HashFilter', label: 'SHA256 (optional)', kind: 'text', mono: true, placeholder: 'Only delete files with this hash' },
      { key: 'MaxFiles', label: 'Skip a host if it matches more than', kind: 'text', initial: '50' },
    ],
    summary: v => `Delete ${v.Glob}`,
  },
  {
    id: 'tasks', group: 'Persistence', title: 'Remove scheduled tasks', icon: <CalendarX />, platforms: 'Windows',
    description: 'Delete scheduled tasks whose command and arguments match the regexes.',
    artifacts: ['Windows.Remediation.ScheduledTasks'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [
      { key: 'CommandRegEx', label: 'Command (regex)', kind: 'text', mono: true, required: true, placeholder: '(?i)evil\\.exe' },
      { key: 'ArgumentRegex', label: 'Arguments (regex)', kind: 'text', mono: true, initial: '.' },
    ],
    summary: v => `Remove scheduled tasks ${v.CommandRegEx}`,
  },
  {
    id: 'service', group: 'Persistence', title: 'Remove service', icon: <Wrench />, platforms: 'Windows',
    description: 'Stop and delete services whose name or binary path matches a regex.',
    artifacts: ['Windows.Remediation.RemoveService'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [{ key: 'ServiceRegex', label: 'Service name or binary path (regex)', kind: 'text', mono: true, required: true, placeholder: '(?i)^EvilSvc$' }],
    summary: v => `Remove service ${v.ServiceRegex}`,
  },
  {
    id: 'disable-user', group: 'Accounts', title: 'Disable local user', icon: <UserX />, platforms: 'Windows',
    description: 'Disable local accounts whose name matches a regex. Domain accounts are not affected.',
    artifacts: ['Windows.Remediation.DisableLocalUser'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [{ key: 'UserRegex', label: 'Account name (regex)', kind: 'text', mono: true, required: true, placeholder: '^backdoor$' }],
    summary: v => `Disable local user ${v.UserRegex}`,
  },
  {
    id: 'enable-user', group: 'Accounts', title: 'Re-enable local user', icon: <UserCheck />, platforms: 'Windows',
    description: 'Re-enable local accounts that were disabled.',
    artifacts: ['Windows.Remediation.DisableLocalUser'], fixed: { Enable: 'Y' }, armParam: 'ReallyDoIt',
    fields: [{ key: 'UserRegex', label: 'Account name (regex)', kind: 'text', mono: true, required: true, placeholder: '^alice$' }],
    summary: v => `Re-enable local user ${v.UserRegex}`,
  },
  {
    id: 'uninstall', group: 'Agent', title: 'Uninstall agent', icon: <PackageX />, platforms: 'Windows, Debian, RedHat',
    description: 'Remove the agent package from the hosts. They stop reporting to this server for good.',
    artifacts: ['Admin.Client.Uninstall'], fixed: {}, armParam: 'ReallyDoIt',
    fields: [{ key: 'DisplayNameRegex', label: 'Package name (regex)', kind: 'text', mono: true, required: true, initial: 'Velociraptor' }],
    summary: () => 'Uninstall agent',
  },
];

export const RESPONSE_TAG = 'response';

export const GROUP_ICON: Record<ResponseGroup, React.ReactNode> = {
  Containment: <ShieldAlert />, Process: <Skull />, File: <FileX2 />, Persistence: <CalendarX />,
  Accounts: <UserX />, Agent: <PackageX />,
};
