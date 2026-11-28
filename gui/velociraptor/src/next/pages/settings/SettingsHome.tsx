// Server settings overview: every administration page in one place.
import { Link } from 'react-router-dom';
import { ChevronRight, Settings2 } from 'lucide-react';
import { Badge, Card } from '../../ui/primitives';
import { useConsoleHttps } from '../../lib/consoleHttps';
import { SETTINGS_GROUPS } from './nav';
import { SETTINGS_ICONS } from './SettingsLayout';

function HttpsBadge() {
  const { data } = useConsoleHttps();
  if (!data || !data.available) return null;
  if (data.pending) return <Badge tone="warn">On trial</Badge>;
  if (data.serving && data.url) return <Badge tone="ok">{new URL(data.url).host}</Badge>;
  return <Badge>Not set up</Badge>;
}

const BADGES: Record<string, () => JSX.Element | null> = { https: HttpsBadge };

export default function SettingsHome() {
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-6 tw:max-w-5xl">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Settings2 className="tw:size-5 tw:text-accent" />Server settings</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">Accounts, access, the console's address and the connections to other tools.</p>
        </div>
        {SETTINGS_GROUPS.map(g => (
          <section key={g.title} className="tw:space-y-2">
            <h2 className="tw:text-2xs tw:font-semibold tw:uppercase tw:tracking-wider tw:text-faint">{g.title}</h2>
            <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:xl:grid-cols-3 tw:gap-3">
              {g.pages.map(p => {
                const Extra = BADGES[p.id];
                return (
                  <Link key={p.id} to={p.to} className="tw:block tw:group">
                    <Card className="tw:h-full tw:p-4 tw:flex tw:gap-3 tw:items-start tw:transition-colors tw:group-hover:border-line-strong">
                      <span className="tw:flex tw:items-center tw:justify-center tw:size-8 tw:rounded-md tw:bg-accent-soft tw:text-accent tw:shrink-0 tw:[&>svg]:size-4">
                        {SETTINGS_ICONS[p.id]}
                      </span>
                      <div className="tw:min-w-0 tw:flex-1">
                        <div className="tw:flex tw:items-center tw:gap-2 tw:text-[13px] tw:font-semibold">
                          {p.label}{Extra && <Extra />}
                        </div>
                        <p className="tw:text-xs tw:text-muted tw:mt-0.5">{p.description}</p>
                      </div>
                      <ChevronRight className="tw:size-4 tw:text-faint tw:group-hover:text-fg tw:shrink-0 tw:mt-2" />
                    </Card>
                  </Link>
                );
              })}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
