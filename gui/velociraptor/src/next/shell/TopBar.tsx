import { useDebounced } from '../lib/hooks';
import { lazy, Suspense, useRef, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Popover } from 'radix-ui';
import {
  Bell, CircleHelp, ExternalLink, Command, Menu as MenuIcon, LogOut, Moon, Settings, Sun, Building2, Keyboard, Check, Monitor, ShieldCheck, Settings2,
} from 'lucide-react';
import { useClientNameSuggest, useTraits } from '../lib/queries';
import { ALL, CATEGORY_LABEL, useMessageAction, useMessages } from '../lib/messages';
import { SeverityIcon } from '../ui/MessageIcon';
import { href } from '../lib/api';
import { clientStatus, timeAgo } from '../lib/format';
import {
  cn, IconButton, Kbd, Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger,
  SearchInput, StatusDot, Tooltip,
} from '../ui/primitives';
import { setTheme } from './theme';
import { useSelectedClient } from './client-context';

const UserSettingsDialog = lazy(() => import('./AccountDialogs').then(m => ({ default: m.UserSettingsDialog })));
const HelpDialog = lazy(() => import('./AccountDialogs').then(m => ({ default: m.HelpDialog })));


function ClientSearch() {
  const history = useHistory();
  const { setClient } = useSelectedClient();
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const debounced = useDebounced(q.trim(), 150);
  const { data: hits = [], isFetching } = useClientNameSuggest(debounced);
  const inputRef = useRef<HTMLInputElement>(null);

  const go = (query: string) => {
    setOpen(false);
    history.push(`/search/${encodeURIComponent(query || 'all')}`);
  };

  const pick = (idx: number) => {
    const c = hits[idx];
    if (!c) return go(q);
    setClient(c);
    setOpen(false);
    setQ('');
    history.push(`/host/${c.client_id}`);
  };

  return (
    <Popover.Root open={open && q.length > 0} onOpenChange={setOpen}>
      <Popover.Anchor asChild>
        <div className="tw:w-full tw:max-w-md">
          <SearchInput
            inputRef={inputRef}
            value={q}
            onChange={v => {
              setQ(v);
              setOpen(true);
              setActive(-1);
            }}
            placeholder="Search clients by host, label:, ip:, client id…"
            onKeyDown={e => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActive(a => Math.min(a + 1, hits.length - 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActive(a => Math.max(a - 1, -1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                if (active >= 0) pick(active);
                else go(q.trim());
              } else if (e.key === 'Escape') {
                setOpen(false);
              }
            }}
          />
          {/* Keeps the legacy alt-key "focus search" hotkey working. */}
          <input id="client-search-bar" className="tw:sr-only" tabIndex={-1} aria-hidden
            onFocus={() => inputRef.current?.focus()} />
        </div>
      </Popover.Anchor>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={6}
          onOpenAutoFocus={e => e.preventDefault()}
          className="rx tw:z-[1600] tw:w-[var(--radix-popover-trigger-width)] tw:min-w-[420px] tw:rounded-lg tw:border tw:border-line tw:bg-raised rx-shadow-lg tw:p-1 tw:animate-fade-in">
          {hits.length === 0 && (
            <div className="tw:px-3 tw:py-2 tw:text-xs tw:text-faint">{isFetching ? 'Searching…' : 'No matching clients'}</div>
          )}
          {hits.map((c, i) => (
            <button key={c.client_id} type="button" onMouseEnter={() => setActive(i)} onClick={() => pick(i)}
              className={cn('tw:flex tw:w-full tw:items-center tw:gap-2.5 tw:rounded-md tw:px-2.5 tw:h-9 tw:text-left',
                i === active ? 'tw:bg-hover' : '')}>
              <StatusDot status={clientStatus(c.last_seen_at)} />
              <span className="tw:font-medium tw:text-[13px] tw:truncate">{c.os_info?.hostname || c.client_id}</span>
              <span className="tw:font-mono tw:text-2xs tw:text-faint">{c.client_id}</span>
              <span className="tw:ml-auto tw:text-2xs tw:text-faint">{timeAgo(c.last_seen_at)}</span>
            </button>
          ))}
          <div className="tw:border-t tw:border-line tw:mt-1 tw:pt-1">
            <button type="button" onClick={() => go(q.trim())}
              className="tw:flex tw:w-full tw:items-center tw:gap-2 tw:rounded-md tw:px-2.5 tw:h-8 tw:text-xs tw:text-muted tw:hover:bg-hover">
              <Monitor className="tw:size-3.5" /> Show all results for “{q}” <Kbd className="tw:ml-auto">Enter</Kbd>
            </button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

// The bell: unread count and the latest messages, full titles, one
// click to read a message or open its link. The full inbox is the
// Messages page.
function MessagesBell() {
  const history = useHistory();
  const [open, setOpen] = useState(false);
  const { data } = useMessages();
  const act = useMessageAction();
  const unread = data?.unread ?? 0;
  // Unread first, then the latest.
  const items = [...(data?.items ?? [])]
    .sort((a, b) => Number(a.read) - Number(b.read) || b.last_seen - a.last_seen)
    .slice(0, 6);
  const go = (path: string) => { setOpen(false); history.push(path); };

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Tooltip content={unread ? `${unread} unread message${unread === 1 ? '' : 's'}` : 'Messages'}>
        <Popover.Trigger asChild>
          <button type="button" aria-label={unread ? `Messages, ${unread} unread` : 'Messages'}
            className="tw:relative tw:flex tw:items-center tw:justify-center tw:size-8 tw:rounded-md tw:text-muted tw:hover:bg-hover tw:hover:text-fg">
            <Bell className="tw:size-4" />
            {unread > 0 && (
              <span className="tw:absolute tw:top-1 tw:right-1 tw:min-w-[14px] tw:h-[14px] tw:px-0.5 tw:rounded-full tw:bg-bad tw:text-white tw:text-[9px] tw:font-bold tw:flex tw:items-center tw:justify-center">
                {unread > 99 ? '99+' : unread}
              </span>
            )}
          </button>
        </Popover.Trigger>
      </Tooltip>
      <Popover.Portal>
        <Popover.Content align="end" sideOffset={6} collisionPadding={8}
          className="rx tw:z-[1600] tw:w-[min(420px,calc(100vw-16px))] tw:rounded-lg tw:border tw:border-line tw:bg-raised rx-shadow-lg tw:animate-fade-in">
          <div className="tw:flex tw:items-center tw:gap-2 tw:px-3 tw:h-10 tw:border-b tw:border-line">
            <span className="tw:text-[13px] tw:font-semibold">Messages</span>
            {unread > 0 && <span className="tw:text-2xs tw:text-muted">{unread} unread</span>}
            {unread > 0 && (
              <button type="button" onClick={() => act.mutate({ action: 'read', ids: [ALL] })}
                className="tw:ml-auto tw:flex tw:items-center tw:gap-1 tw:text-2xs tw:text-muted tw:hover:text-fg">
                <Check className="tw:size-3" /> Mark all read
              </button>
            )}
          </div>
          <div className="tw:max-h-[60vh] tw:overflow-y-auto">
            {items.length === 0 && <div className="tw:px-3 tw:py-6 tw:text-center tw:text-xs tw:text-faint">No messages</div>}
            {items.map(m => (
              <div key={m.id} className="tw:flex tw:gap-2.5 tw:px-3 tw:py-2.5 tw:border-b tw:border-line tw:last:border-b-0 tw:hover:bg-hover">
                <span className="tw:pt-0.5 tw:flex tw:flex-col tw:items-center tw:gap-1.5">
                  <SeverityIcon m={m} />
                  {!m.read && <span className="tw:size-2 tw:rounded-full tw:bg-accent" aria-label="Unread" />}
                </span>
                <div className="tw:min-w-0 tw:flex-1">
                  <button type="button" onClick={() => go(`/messages/${m.id}`)}
                    className={cn('tw:block tw:text-left tw:text-[13px] tw:leading-snug tw:break-words tw:hover:text-accent',
                      m.read ? 'tw:text-muted' : 'tw:font-semibold')}>
                    {m.title}
                  </button>
                  <div className="tw:mt-1 tw:flex tw:flex-wrap tw:items-center tw:gap-x-2 tw:text-2xs tw:text-faint">
                    <span>{CATEGORY_LABEL[m.category]}</span>
                    <span>{timeAgo(m.last_seen)}</span>
                    {m.link && (
                      <a href={m.link} target="_blank" rel="noopener noreferrer"
                        onClick={() => { if (!m.read) act.mutate({ action: 'read', ids: [m.id] }); }}
                        className="tw:ml-auto tw:inline-flex tw:items-center tw:gap-1 tw:text-accent tw:hover:underline">
                        {m.link_host || 'Open'} <ExternalLink className="tw:size-3" />
                      </a>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <button type="button" onClick={() => go('/messages')}
            className="tw:w-full tw:h-9 tw:border-t tw:border-line tw:text-xs tw:font-medium tw:text-accent tw:hover:bg-hover tw:rounded-b-lg">
            {data && data.total > items.length ? `See all ${data.total} messages` : 'Open messages'}
          </button>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

function initials(name: string | undefined) {
  if (!name) return '?';
  return name.slice(0, 2).toUpperCase();
}

export default function TopBar({ onOpenPalette, dark, onOpenNav }: { onOpenPalette: () => void; dark: boolean; onOpenNav?: () => void }) {
  const ctx = useTraits();
  const { traits, updateTraits } = ctx;
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const orgs = traits?.orgs ?? [];
  const currentOrg = window.globals?.OrgId || traits?.org || 'root';
  const orgLabel = (id: string, name?: string) => (id === 'root' || name === '<root>' ? 'Root organization' : name);
  const orgName = orgLabel(currentOrg, traits?.org_name || orgs.find(o => o.id === currentOrg)?.name);
  const perms = traits?.Permissions;
  const canManageOrgs = !!perms && (perms.org_admin || perms.server_admin);

  const switchOrg = (org: string) => {
    window.location.assign(href('/app/index.html', { org_id: org }) + '#/dashboard');
  };

  const isMac = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform);

  return (
    <header className="tw:flex tw:items-center tw:gap-2 tw:md:gap-3 tw:h-12 tw:px-2 tw:md:px-4 tw:border-b tw:border-line tw:bg-panel tw:shrink-0">
      {onOpenNav && <IconButton label="Open navigation" onClick={onOpenNav} icon={<MenuIcon className="tw:size-4" />} />}
      <ClientSearch />

      <button type="button" onClick={onOpenPalette}
        className="tw:hidden tw:md:flex tw:items-center tw:gap-2 tw:h-8 tw:px-2.5 tw:rounded-md tw:border tw:border-line tw:text-xs tw:text-faint tw:hover:bg-hover tw:hover:text-fg">
        <Command className="tw:size-3.5" />
        Jump to…
        <span className="tw:flex tw:gap-0.5"><Kbd>{isMac ? '⌘' : 'Ctrl'}</Kbd><Kbd>K</Kbd></span>
      </button>

      <div className="tw:ml-auto tw:flex tw:items-center tw:gap-1">
        {orgName && (orgs.length > 1 || canManageOrgs) && (
          <Menu>
            <MenuTrigger asChild>
              <button type="button" className="tw:flex tw:items-center tw:gap-1.5 tw:h-8 tw:px-2.5 tw:rounded-md tw:text-xs tw:font-medium tw:text-muted tw:hover:bg-hover">
                <Building2 className="tw:size-3.5" /> <span className="tw:hidden tw:sm:inline">{orgName}</span>
              </button>
            </MenuTrigger>
            <MenuContent>
              <MenuLabel>Switch organization</MenuLabel>
              {orgs.map(o => (
                <MenuItem key={o.id} onSelect={() => switchOrg(o.id)}
                  icon={o.id === currentOrg ? <Check /> : <span className="tw:size-3.5" />}>{orgLabel(o.id, o.name)}</MenuItem>
              ))}
              {canManageOrgs && <>
                <MenuSeparator />
                <MenuItem icon={<Settings2 />} onSelect={() => { window.location.hash = '/orgs'; }}>Manage organizations…</MenuItem>
              </>}
            </MenuContent>
          </Menu>
        )}

        <MessagesBell />

        <IconButton label="Help" className="tw:max-sm:hidden" onClick={() => setHelpOpen(true)} icon={<CircleHelp className="tw:size-4" />} />

        <IconButton label={dark ? 'Light mode' : 'Dark mode'}
          onClick={() => setTheme(!dark, traits?.ui_settings, updateTraits)}
          icon={dark ? <Sun className="tw:size-4" /> : <Moon className="tw:size-4" />} />

        <Menu>
          <MenuTrigger asChild>
            <button type="button" className="tw:flex tw:items-center tw:gap-2 tw:h-8 tw:pl-1 tw:pr-2 tw:rounded-md tw:hover:bg-hover tw:ml-1">
              {traits?.picture
                ? <img src={traits.picture} alt="" className="tw:size-6 tw:rounded-full" />
                : <span className="tw:flex tw:items-center tw:justify-center tw:size-6 tw:rounded-full tw:bg-accent tw:text-accent-fg tw:text-2xs tw:font-bold">{initials(traits?.username)}</span>}
              <span className="tw:text-[13px] tw:font-medium tw:hidden tw:lg:inline">{traits?.username}</span>
            </button>
          </MenuTrigger>
          <MenuContent>
            <MenuLabel>{traits?.username}{orgName ? ` · ${orgName}` : ''}</MenuLabel>
            <MenuItem icon={<Settings />} onSelect={() => setSettingsOpen(true)}>Settings…</MenuItem>
            <MenuItem icon={<ShieldCheck />} onSelect={() => { window.location.hash = '/account/security'; }}>Password and two-factor…</MenuItem>
            <MenuItem icon={dark ? <Sun /> : <Moon />} onSelect={() => setTheme(!dark, traits?.ui_settings, updateTraits)}>
              {dark ? 'Light mode' : 'Dark mode'}
            </MenuItem>
            <MenuItem icon={<Keyboard />} shortcut="?" onSelect={() => {
              document.dispatchEvent(new KeyboardEvent('keydown', { key: '?', shiftKey: true, bubbles: true }));
            }}>Keyboard shortcuts</MenuItem>
            <MenuSeparator />
            <MenuItem icon={<LogOut />} onSelect={() => {
              window.location.assign(href('/app/logoff.html', { username: traits?.username }));
            }}>Sign out</MenuItem>
          </MenuContent>
        </Menu>
      </div>

      <Suspense fallback={null}>
        {settingsOpen && <UserSettingsDialog onClose={() => setSettingsOpen(false)} />}
        {helpOpen && <HelpDialog onClose={() => setHelpOpen(false)} />}
      </Suspense>
    </header>
  );
}
