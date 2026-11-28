import { lazy, Suspense, useEffect, useState } from 'react';
import { Link, Redirect, Route, Switch } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import CommandPalette from './CommandPalette';
import SettingsLayout from '../pages/settings/SettingsLayout';
import { useThemeSync } from './theme';
import { EmptyState, Spinner, cn } from '../ui/primitives';
import { Compass } from 'lucide-react';
import { ErrorBoundary } from './ErrorBoundary';
import { usePhone } from '../ui/MobileBack';
import { useLocation } from 'react-router-dom';

const Dashboard = lazy(() => import('../pages/dashboard/Dashboard'));
const HuntsPage = lazy(() => import('../pages/hunts/HuntsPage'));
const ResponsePage = lazy(() => import('../pages/response/ResponsePage'));
const CasesPage = lazy(() => import('../pages/cases/CasesPage'));
const IocSweepPage = lazy(() => import('../pages/ioc/IocSweepPage'));
const IntegrationsPage = lazy(() => import('../pages/integrations/IntegrationsPage'));
const FleetHealthPage = lazy(() => import('../pages/fleet/FleetHealthPage'));
const UpdatesPage = lazy(() => import('../pages/updates/UpdatesPage'));
const MessagesPage = lazy(() => import('../pages/messages/MessagesPage'));
const FeedsPage = lazy(() => import('../pages/feeds/FeedsPage'));
const GroupsPage = lazy(() => import('../pages/users/GroupsPage'));
const OrgsPage = lazy(() => import('../pages/orgs/OrgsPage'));
const ApiKeysPage = lazy(() => import('../pages/apikeys/ApiKeysPage'));
const NetworkPage = lazy(() => import('../pages/network/NetworkPage'));
const SecurityPage = lazy(() => import('../pages/account/SecurityPage'));
const ClientsPage = lazy(() => import('../pages/clients/ClientsPage'));
const ClientOverview = lazy(() => import('../pages/host/ClientOverview'));
const ShellPage = lazy(() => import('../pages/host/ShellPage'));
const ServerOverview = lazy(() => import('../pages/host/ServerOverview'));
const ArtifactsPage = lazy(() => import('../pages/artifacts/ArtifactsPage'));
const FileBrowser = lazy(() => import('../pages/vfs/FileBrowser'));
const CollectionsPage = lazy(() => import('../pages/collections/CollectionsPage'));
const UsersPage = lazy(() => import('../pages/users/UsersPage'));
const SecretsPage = lazy(() => import('../pages/secrets/SecretsPage'));
const EventsPage = lazy(() => import('../pages/events/EventsPage'));
const NotebooksPage = lazy(() => import('../pages/notebooks/NotebooksPage'));
const SettingsHome = lazy(() => import('../pages/settings/SettingsHome'));
const DeployPage = lazy(() => import('../pages/settings/DeployPage'));
const AgentConnectionsPage = lazy(() => import('../pages/settings/AgentConnectionsPage'));
const HttpsPage = lazy(() => import('../pages/settings/HttpsPage'));
const AuditPage = lazy(() => import('../pages/settings/AuditPage'));

// The settings pages share the Server settings frame. They keep their
// own addresses so existing links keep working.
const SETTINGS_ROUTES = ['/settings', '/users', '/groups', '/orgs', '/account/security', '/network', '/updates', '/integrations', '/apikeys', '/secrets'];

function PageFallback() {
  return (
    <div className="tw:flex tw:flex-1 tw:items-center tw:justify-center">
      <Spinner className="tw:size-5" />
    </div>
  );
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem('rx-sidebar-collapsed') === '1';
  } catch {
    return false;
  }
}

export default function AppShell() {
  const dark = useThemeSync();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const phone = usePhone();
  const [navOpen, setNavOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setNavOpen(false), [pathname]);

  useEffect(() => {
    try {
      localStorage.setItem('rx-sidebar-collapsed', collapsed ? '1' : '0');
    } catch {
      // ignore
    }
  }, [collapsed]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(o => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="rx tw:fixed tw:inset-0 tw:flex tw:bg-canvas tw:text-fg">
      {phone && navOpen && <div className="tw:fixed tw:inset-0 tw:z-40" style={{ background: "rgb(0 0 0 / 0.45)" }} onClick={() => setNavOpen(false)} />}
      <Sidebar collapsed={collapsed && !phone} onToggle={() => (phone ? setNavOpen(false) : setCollapsed(c => !c))}
        className={phone ? cn('tw:fixed tw:inset-y-0 tw:left-0 tw:z-50 tw:shadow-xl', !navOpen && 'tw:hidden') : undefined} />
      <div className="tw:flex tw:flex-col tw:flex-1 tw:min-w-0">
        <TopBar onOpenPalette={() => setPaletteOpen(true)} dark={dark} onOpenNav={phone ? () => setNavOpen(true) : undefined} />
        <main className="tw:flex tw:flex-col tw:flex-1 tw:min-h-0 tw:relative">
          <ErrorBoundary>
            <Suspense fallback={<PageFallback />}>
              <Switch>
                <Route exact path={['/', '/welcome', '/dashboard']}>
                  <Dashboard />
                </Route>
                <Route path={SETTINGS_ROUTES}>
                  <SettingsLayout>
                    <Suspense fallback={<PageFallback />}>
                      <Switch>
                        <Route path="/settings" exact><SettingsHome /></Route>
                        <Route path="/settings/https"><HttpsPage /></Route>
                        <Route path="/settings/audit"><AuditPage /></Route>
                        <Route path="/users/:user?"><UsersPage /></Route>
                        <Route path="/groups"><GroupsPage /></Route>
                        <Route path="/orgs"><OrgsPage /></Route>
                        <Route path="/settings/deploy"><DeployPage /></Route>
                        <Route path="/settings/agents"><AgentConnectionsPage /></Route>
                        <Route path="/account/security"><SecurityPage /></Route>
                        <Route path="/network"><NetworkPage /></Route>
                        <Route path="/updates"><UpdatesPage /></Route>
                        <Route path="/integrations"><IntegrationsPage /></Route>
                        <Route path="/apikeys"><ApiKeysPage /></Route>
                        <Route path="/secrets/:type?"><SecretsPage /></Route>
                        <Route><Redirect to="/settings" /></Route>
                      </Switch>
                    </Suspense>
                  </SettingsLayout>
                </Route>
                <Route path="/hunts/:hunt_id?/:tab?">
                  <HuntsPage />
                </Route>
                <Route path="/response/:action?">
                  <ResponsePage />
                </Route>
                <Route path="/cases/:case_id?">
                  <CasesPage />
                </Route>
                <Route path="/ioc">
                  <IocSweepPage />
                </Route>
                <Route path="/fleet">
                  <FleetHealthPage />
                </Route>
                <Route path="/feeds">
                  <FeedsPage />
                </Route>
                <Route path="/messages/:id?">
                  <MessagesPage />
                </Route>
                <Route path="/search/:query?">
                  <ClientsPage />
                </Route>
                <Route path="/host/:client_id(C\.[^/]+|server)/shell">
                  <ShellPage />
                </Route>
                <Route path="/host/:client_id(C\.[^/]+)/:action?">
                  <ClientOverview />
                </Route>
                <Route path="/host/server">
                  <ServerOverview />
                </Route>
                <Route path="/vfs/:client_id/:vfs_path(.*)?">
                  <FileBrowser />
                </Route>
                <Route path="/artifacts/:artifact?/:action?">
                  <ArtifactsPage />
                </Route>
                <Route path="/collected/:client_id/:flow_id?/:tab?">
                  <CollectionsPage />
                </Route>
                <Route path={['/events/:client_id(server)/:artifact?', '/events/:client_id(C\.[^/]+)/:artifact?']}>
                  <EventsPage />
                </Route>
                <Route path="/events" exact>
                  <Redirect to="/events/server" />
                </Route>
                <Route path="/notebooks/:notebook_id?" exact>
                  <NotebooksPage />
                </Route>
                {/* Addresses of the old interface open the matching page. */}
                <Route path="/classic/collected/server" exact><Redirect to="/collected/server?collector=1" /></Route>
                <Route path="/classic/dashboard"><Redirect to="/" /></Route>
                <Route path="/classic" render={({ location }) => (
                  <Redirect to={{ pathname: location.pathname.replace(/^\/classic/, '') || '/', search: location.search }} />
                )} />
                <Route>
                  <NotFound />
                </Route>
              </Switch>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} dark={dark} />
    </div>
  );
}

function NotFound() {
  return (
    <div className="tw:flex-1 tw:flex tw:items-center tw:justify-center tw:p-6">
      <EmptyState icon={<Compass />} title="Page not found"
        action={<Link to="/" className="tw:text-sm tw:text-accent tw:hover:underline">Go to the dashboard</Link>}>
        This address does not exist in the console.
      </EmptyState>
    </div>
  );
}
