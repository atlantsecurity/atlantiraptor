import { useDebounced } from '../lib/hooks';
import { useEffect, useState } from 'react';
import { Command } from 'cmdk';
import { Dialog as RDialog } from 'radix-ui';
import { useHistory } from 'react-router-dom';
import {
  Crosshair, LayoutDashboard, Monitor, BookOpen, Package, Server, Radio, Users, KeyRound, Plus,
  Moon, Sun, Search, CornerDownLeft, Zap, FolderTree, History, UserPlus, FilePlus2,
  Siren, Briefcase, ScanSearch, HeartPulse, Plug, Code2, Network, UsersRound, ShieldCheck, Radar, ShieldAlert,
} from 'lucide-react';
import { useArtifactSearch, useClientNameSuggest, useHunts, useNotebookList, useTraits } from '../lib/queries';
import { classify, parseIocs, refang } from '../pages/ioc/parse';
import { prefillIocSweep, rapidHuntUrl } from '../lib/prefill';
import { CASE_PREFIX } from '../pages/cases/model';
import { clientStatus, timeAgo } from '../lib/format';
import { Kbd, StatusDot } from '../ui/primitives';
import { HuntStateBadge } from '../pages/hunts/HuntBits';
import { setTheme } from './theme';
import { useSelectedClient } from './client-context';


const itemCls = 'tw:flex tw:items-center tw:gap-2.5 tw:h-9 tw:px-3 tw:mx-1 tw:rounded-md tw:text-[13px] tw:cursor-pointer tw:[&>svg]:size-4 tw:[&>svg]:text-faint';

export default function CommandPalette({ open, onOpenChange, dark }: {
  open: boolean; onOpenChange: (v: boolean) => void; dark: boolean;
}) {
  const history = useHistory();
  const { traits, updateTraits } = useTraits();
  const { client: selClient, setClient } = useSelectedClient();
  const [q, setQ] = useState('');
  const dq = useDebounced(q.trim(), 150);
  // Only fetch while the palette is open: it is mounted on every page.
  const { data: hunts = [] } = useHunts(false, open);
  const { data: notebooks = [] } = useNotebookList(open);
  const perms = traits?.Permissions;
  const isAdmin = !perms || perms.org_admin || perms.server_admin;
  const { data: clients = [] } = useClientNameSuggest(open ? dq : '');
  const { data: artifacts = [] } = useArtifactSearch(dq, '', open && dq.length >= 2);

  useEffect(() => {
    if (!open) setQ('');
  }, [open]);

  const go = (path: string) => {
    onOpenChange(false);
    history.push(path);
  };

  const ql = dq.toLowerCase();
  const huntHits = (ql
    ? hunts.filter(h => `${h.hunt_id} ${h.hunt_description ?? ''} ${(h.artifacts ?? []).join(' ')} ${(h.tags ?? []).join(' ')}`
      .toLowerCase().includes(ql))
    : hunts).slice(0, 6);

  const navAll = [
    { label: 'Dashboard', icon: <LayoutDashboard />, to: '/dashboard', keys: 'home alerts rapid' },
    { label: 'Hunts', icon: <Crosshair />, to: '/hunts', keys: 'hunt manager' },
    { label: 'Response', icon: <Siren />, to: '/response', keys: 'quarantine isolate kill delete respond approvals' },
    { label: 'Cases', icon: <Briefcase />, to: '/cases', keys: 'incidents investigations' },
    { label: 'IOC sweep', icon: <ScanSearch />, to: '/ioc', keys: 'indicators hashes ioc' },
    { label: 'Clients', icon: <Monitor />, to: '/search/all', keys: 'endpoints hosts' },
    { label: 'Notebooks', icon: <BookOpen />, to: '/notebooks', keys: '' },
    { label: 'Fleet health', icon: <HeartPulse />, to: '/fleet', keys: 'agents versions upgrade' },
    { label: 'Artifacts', icon: <Package />, to: '/artifacts', keys: 'vql' },
    { label: 'Server collections', icon: <Server />, to: '/collected/server', keys: 'server artifacts' },
    { label: 'Server events', icon: <Radio />, to: '/events/server', keys: 'monitoring' },
    ...(isAdmin ? [
      { label: 'Users', icon: <Users />, to: '/users', keys: 'admin accounts' },
      { label: 'Groups', icon: <UsersRound />, to: '/groups', keys: 'admin teams' },
      { label: 'Security and 2FA', icon: <ShieldCheck />, to: '/account/security', keys: 'mfa totp password policy' },
      { label: 'Secrets', icon: <KeyRound />, to: '/secrets', keys: 'credentials' },
      { label: 'Integrations', icon: <Plug />, to: '/integrations', keys: 'email teams slack ai threat intel' },
      { label: 'API keys', icon: <Code2 />, to: '/apikeys', keys: 'siem soar integration' },
      { label: 'Network access', icon: <Network />, to: '/network', keys: 'allowlist ip firewall' },
    ] : []),
  ];
  const navHits = navAll.filter(n => !ql || `${n.label} ${n.keys}`.toLowerCase().includes(ql));

  // Cases and notebooks (cases are notebooks with a case record).
  const docHits = ql.length >= 2 ? notebooks
    .map(r => ({
      id: String(r.NotebookId ?? ''),
      name: String(r.Name ?? ''),
      isCase: String(r.Description ?? '').startsWith(CASE_PREFIX),
    }))
    .filter(n => n.id && `${n.name} ${n.id}`.toLowerCase().includes(ql))
    .slice(0, 6) : [];

  // A pasted indicator: offer to hunt for it straight away.
  // The input is one line, so a pasted list arrives space separated.
  const lines = q.split(/[\s,;]+/).map(l => l.trim()).filter(Boolean);
  const single = lines.length === 1 ? refang(lines[0]) : '';
  const singleType = single ? (/^[a-z][a-z0-9+.-]*:\/\//i.test(single) ? 'url' : classify(single)) : null;
  const multi = lines.length > 1 ? parseIocs(lines.join('\n')).iocs.length : 0;
  const rapidable = singleType === 'domain' || singleType === 'ip' || singleType === 'url';
  const sweepable = !!singleType && !rapidable;

  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="rx tw:fixed tw:inset-0 tw:z-[1700] tw:bg-black/30 tw:animate-fade-in" />
        <RDialog.Content aria-describedby={undefined}
          className="rx tw:fixed tw:left-1/2 tw:top-[12vh] tw:z-[1701] tw:-translate-x-1/2 tw:w-[640px] tw:max-w-[calc(100vw-32px)] tw:rounded-xl tw:border tw:border-line tw:bg-raised rx-shadow-lg tw:overflow-hidden tw:animate-fade-in">
          <RDialog.Title className="tw:sr-only">Command palette</RDialog.Title>
          <Command shouldFilter={false} loop>
            <div className="tw:flex tw:items-center tw:gap-2 tw:px-4 tw:border-b tw:border-line">
              <Search className="tw:size-4 tw:text-faint" />
              <Command.Input value={q} onValueChange={setQ} autoFocus
                placeholder="Search anything, or paste an IP, domain, hash or file path…"
                className="tw:flex-1 tw:h-12 tw:bg-transparent tw:outline-none tw:text-[14px] tw:placeholder:text-faint" />
              <Kbd>Esc</Kbd>
            </div>
            <Command.List className="tw:max-h-[min(60vh,480px)] tw:overflow-y-auto tw:py-1">
              <Command.Empty className="tw:px-4 tw:py-6 tw:text-center tw:text-xs tw:text-faint">No results</Command.Empty>

              {(rapidable || sweepable || multi > 0) && (
                <Command.Group heading="Hunt for this indicator">
                  {rapidable && (
                    <Command.Item value="rapid-hunt" onSelect={() => go(rapidHuntUrl(single))} className={itemCls}>
                      <Radar /> Rapid hunt: who visited <span className="tw:font-mono tw:truncate">{single}</span>
                    </Command.Item>
                  )}
                  {(sweepable || rapidable) && (
                    <Command.Item value="ioc-sweep-one" onSelect={() => { prefillIocSweep(single); go('/ioc'); }} className={itemCls}>
                      <ScanSearch /> IOC sweep for <span className="tw:font-mono tw:truncate">{single}</span>
                      <span className="tw:ml-auto tw:text-2xs tw:text-faint">{singleType}</span>
                    </Command.Item>
                  )}
                  {multi > 0 && (
                    <Command.Item value="ioc-sweep-many" onSelect={() => { prefillIocSweep(lines.join('\n')); go('/ioc'); }} className={itemCls}>
                      <ScanSearch /> IOC sweep for {multi} pasted indicator{multi === 1 ? '' : 's'}
                    </Command.Item>
                  )}
                </Command.Group>
              )}

              {!ql && (
                <Command.Group heading="Actions">
                  <Command.Item value="new-hunt" onSelect={() => go('/hunts?new=1')} className={itemCls}>
                    <Plus /> New hunt
                  </Command.Item>
                  {selClient?.client_id && selClient.client_id !== 'server' && <>
                    <Command.Item value="collect-client" onSelect={() => go(`/collected/${selClient.client_id}?new=1`)} className={itemCls}>
                      <Zap /> Collect from {selClient.os_info?.hostname || selClient.client_id}
                    </Command.Item>
                    <Command.Item value="client-collections" onSelect={() => go(`/collected/${selClient.client_id}`)} className={itemCls}>
                      <History /> Collections on {selClient.os_info?.hostname || selClient.client_id}
                    </Command.Item>
                    <Command.Item value="client-files" onSelect={() => go(`/vfs/${selClient.client_id}/`)} className={itemCls}>
                      <FolderTree /> Browse files on {selClient.os_info?.hostname || selClient.client_id}
                    </Command.Item>
                  </>}
                  <Command.Item value="new-artifact" onSelect={() => go('/artifacts?new=1')} className={itemCls}>
                    <FilePlus2 /> New artifact
                  </Command.Item>
                  <Command.Item value="new-notebook" onSelect={() => go('/notebooks?new=1')} className={itemCls}>
                    <BookOpen /> New notebook
                  </Command.Item>
                  <Command.Item value="new-user" onSelect={() => go('/users?add=1')} className={itemCls}>
                    <UserPlus /> Add a user
                  </Command.Item>
                  <Command.Item value="theme" onSelect={() => {
                    onOpenChange(false);
                    setTheme(!dark, traits?.ui_settings, updateTraits);
                  }} className={itemCls}>
                    {dark ? <Sun /> : <Moon />} Switch to {dark ? 'light' : 'dark'} mode
                  </Command.Item>
                </Command.Group>
              )}

              {navHits.length > 0 && <Command.Group heading="Pages">
                {navHits.map(n => (
                  <Command.Item key={n.to} value={`nav-${n.to}`} onSelect={() => go(n.to)} className={itemCls}>
                    {n.icon} {n.label}
                  </Command.Item>
                ))}
              </Command.Group>}

              {huntHits.length > 0 && (
                <Command.Group heading="Hunts">
                  {huntHits.map(h => (
                    <Command.Item key={h.hunt_id} value={`hunt-${h.hunt_id}`} onSelect={() => go(`/hunts/${h.hunt_id}`)} className={itemCls}>
                      <Crosshair />
                      <span className="tw:truncate tw:flex-1">{h.hunt_description || (h.artifacts ?? []).join(', ')}</span>
                      <span className="tw:font-mono tw:text-2xs tw:text-faint">{h.hunt_id}</span>
                      <HuntStateBadge hunt={h} />
                    </Command.Item>
                  ))}
                </Command.Group>
              )}

              {ql && clients.length > 0 && (
                <Command.Group heading="Clients">
                  {clients.map(c => (
                    <Command.Item key={c.client_id} value={`client-${c.client_id}`} onSelect={() => {
                      setClient(c);
                      go(`/host/${c.client_id}`);
                    }} className={itemCls}>
                      <StatusDot status={clientStatus(c.last_seen_at)} />
                      <span className="tw:truncate tw:flex-1">{c.os_info?.hostname || c.client_id}</span>
                      <span className="tw:font-mono tw:text-2xs tw:text-faint">{c.client_id}</span>
                      <span className="tw:text-2xs tw:text-faint tw:w-20 tw:text-right">{timeAgo(c.last_seen_at)}</span>
                    </Command.Item>
                  ))}
                  {clients[0] && (
                    <Command.Item value="client-respond" onSelect={() => go(`/response/quarantine?client=${clients[0].client_id}`)} className={itemCls}>
                      <ShieldAlert /> Respond on {clients[0].os_info?.hostname || clients[0].client_id} (quarantine, kill, delete)…
                    </Command.Item>
                  )}
                  <Command.Item value="client-search-all" onSelect={() => go(`/search/${encodeURIComponent(dq)}`)} className={itemCls}>
                    <Monitor /> Search all clients for “{dq}”
                  </Command.Item>
                </Command.Group>
              )}

              {docHits.length > 0 && (
                <Command.Group heading="Cases and notebooks">
                  {docHits.map(n => (
                    <Command.Item key={n.id} value={`doc-${n.id}`} onSelect={() => go(n.isCase ? `/cases/${n.id}` : `/notebooks/${n.id}`)} className={itemCls}>
                      {n.isCase ? <Briefcase /> : <BookOpen />}
                      <span className="tw:truncate tw:flex-1">{n.name}</span>
                      <span className="tw:font-mono tw:text-2xs tw:text-faint">{n.id}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}

              {ql.length >= 2 && artifacts.length > 0 && (
                <Command.Group heading="Artifacts">
                  {artifacts.slice(0, 6).map(a => (
                    <Command.Item key={a.name} value={`artifact-${a.name}`} onSelect={() => go(`/artifacts/${a.name}`)} className={itemCls}>
                      <Package />
                      <span className="tw:truncate">{a.name}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
            </Command.List>
            <div className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:h-9 tw:border-t tw:border-line tw:text-2xs tw:text-faint">
              <span className="tw:flex tw:items-center tw:gap-1"><Kbd>↑</Kbd><Kbd>↓</Kbd> navigate</span>
              <span className="tw:flex tw:items-center tw:gap-1"><Kbd><CornerDownLeft className="tw:size-2.5" /></Kbd> open</span>
            </div>
          </Command>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}
