// Frame for the Server settings section: the section's own navigation
// beside (or, on a phone, above) the page.
import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Building2, CloudDownload, ShieldHalf, Code2, KeyRound, LayoutGrid, Lock, Network, Plug, Rocket, ScrollText, Settings2, ShieldCheck, Users, UsersRound,
} from 'lucide-react';
import { cn } from '../../ui/primitives';
import { usePhone } from '../../ui/MobileBack';
import { SETTINGS_GROUPS, activeSettingsPage } from './nav';

export const SETTINGS_ICONS: Record<string, React.ReactNode> = {
  users: <Users />,
  groups: <UsersRound />,
  orgs: <Building2 />,
  security: <ShieldCheck />,
  audit: <ScrollText />,
  https: <Lock />,
  network: <Network />,
  updates: <CloudDownload />,
  deploy: <Rocket />,
  agents: <ShieldHalf />,
  integrations: <Plug />,
  apikeys: <Code2 />,
  secrets: <KeyRound />,
};

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  const phone = usePhone();
  const active = activeSettingsPage(pathname);
  const overview = pathname === '/settings';

  if (phone) {
    return (
      <div className="tw:flex tw:flex-col tw:flex-1 tw:min-h-0">
        <nav aria-label="Server settings" className="tw:flex tw:gap-1 tw:overflow-x-auto tw:border-b tw:border-line tw:bg-sidebar tw:px-3 tw:py-2 tw:shrink-0">
          <Chip to="/settings" active={overview} icon={<LayoutGrid />}>All settings</Chip>
          {SETTINGS_GROUPS.flatMap(g => g.pages).map(p => (
            <Chip key={p.id} to={p.to} active={active?.id === p.id} icon={SETTINGS_ICONS[p.id]}>{p.label}</Chip>
          ))}
        </nav>
        <div className="tw:flex tw:flex-col tw:flex-1 tw:min-h-0">{children}</div>
      </div>
    );
  }

  return (
    <div className="tw:flex tw:flex-1 tw:min-h-0">
      <nav aria-label="Server settings" className="tw:w-56 tw:shrink-0 tw:overflow-y-auto tw:border-r tw:border-line tw:bg-sidebar tw:px-2 tw:pb-4">
        <NavLink to="/settings" exact
          className={cn('tw:mt-3 tw:flex tw:items-center tw:gap-2 tw:h-8 tw:px-2.5 tw:rounded-md tw:text-[13px] tw:font-semibold',
            overview ? 'tw:bg-active tw:text-fg' : 'tw:text-fg tw:hover:bg-hover')}>
          <Settings2 className={cn('tw:size-4', overview && 'tw:text-accent')} />Server settings
        </NavLink>
        {SETTINGS_GROUPS.map(g => (
          <div key={g.title} className="tw:space-y-0.5">
            <div className="tw:px-2.5 tw:pt-4 tw:pb-1 tw:text-2xs tw:font-semibold tw:uppercase tw:tracking-wider tw:text-faint">{g.title}</div>
            {g.pages.map(p => {
              const on = active?.id === p.id;
              return (
                <NavLink key={p.id} to={p.to}
                  className={cn('tw:flex tw:items-center tw:gap-2.5 tw:h-8 tw:px-2.5 tw:rounded-md tw:text-[13px] tw:font-medium',
                    on ? 'tw:bg-active tw:text-fg' : 'tw:text-muted tw:hover:bg-hover tw:hover:text-fg')}>
                  <span className={cn('tw:flex tw:[&>svg]:size-4', on && 'tw:text-accent')}>{SETTINGS_ICONS[p.id]}</span>
                  <span className="tw:truncate">{p.label}</span>
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="tw:flex tw:flex-col tw:flex-1 tw:min-w-0 tw:min-h-0">{children}</div>
    </div>
  );
}

function Chip({ to, active, icon, children }: { to: string; active: boolean; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <NavLink to={to} exact
      className={cn('tw:flex tw:items-center tw:gap-1.5 tw:h-7 tw:px-2.5 tw:rounded-full tw:text-xs tw:font-medium tw:whitespace-nowrap tw:border',
        active ? 'tw:bg-active tw:text-fg tw:border-line-strong' : 'tw:text-muted tw:border-line')}>
      <span className="tw:flex tw:[&>svg]:size-3.5">{icon}</span>{children}
    </NavLink>
  );
}
