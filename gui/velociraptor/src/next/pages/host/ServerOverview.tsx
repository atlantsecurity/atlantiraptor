// The server's own page (/host/server): its health, its metadata (the
// key/value store server artifacts read their settings from), and the
// places where you work with the server.
import { Link } from 'react-router-dom';
import { Activity, BookOpen, Briefcase, History, Radio, Server, Settings, Terminal } from 'lucide-react';
import { Card, CardHeader } from '../../ui/primitives';
import { ServerHealth } from '../dashboard/Dashboard';
import { Metadata } from './ClientOverview';

const PLACES = [
  { to: '/collected/server', icon: <History />, title: 'Server collections', text: 'Run server artifacts and see their results.' },
  { to: '/collected/server?collector=1', icon: <Briefcase />, title: 'Offline collector', text: 'Build a standalone collector for machines without an agent.' },
  { to: '/events/server', icon: <Radio />, title: 'Server events', text: 'Results of the server monitoring artifacts.' },
  { to: '/host/server/shell', icon: <Terminal />, title: 'Server shell', text: 'Run a command or VQL on the server itself.' },
  { to: '/notebooks', icon: <BookOpen />, title: 'Notebooks', text: 'Query collected data with VQL.' },
  { to: '/settings', icon: <Settings />, title: 'Server settings', text: 'Users, updates, HTTPS, network access and more.' },
];

export default function ServerOverview() {
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Server className="tw:size-5 tw:text-accent" />Server</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">The Atlantiraptor server: its health, its settings for server artifacts, and server-side work.</p>
        </div>

        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:xl:grid-cols-3 tw:gap-3">
          {PLACES.map(p => (
            <Link key={p.to} to={p.to} className="tw:flex tw:items-start tw:gap-3 tw:rounded-lg tw:border tw:border-line tw:bg-panel tw:p-3 tw:hover:border-accent tw:hover:bg-hover">
              <span className="tw:flex tw:size-8 tw:shrink-0 tw:items-center tw:justify-center tw:rounded-lg tw:bg-accent-soft tw:text-accent tw:[&>svg]:size-4">{p.icon}</span>
              <span className="tw:min-w-0">
                <span className="tw:block tw:text-[13px] tw:font-medium">{p.title}</span>
                <span className="tw:block tw:text-2xs tw:text-muted">{p.text}</span>
              </span>
            </Link>
          ))}
        </div>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-[1fr_420px] tw:gap-4 tw:items-start">
          <ServerHealth />
          <Card>
            <CardHeader icon={<Activity className="tw:size-4" />} title="Server metadata"
              subtitle="Settings that server artifacts read, such as webhook addresses or API tokens." />
            <Metadata clientId="server" />
          </Card>
        </div>
      </div>
    </div>
  );
}
