import { lazy, Suspense } from 'react';
import { HashRouter, Redirect, Route, Switch } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { queryClient } from './lib/queries';
import { ClientProvider } from './shell/client-context';
import { TooltipProvider } from './ui/primitives';
import AppShell from './shell/AppShell';
import { Hotkeys } from './shell/Hotkeys';
import { UserSettings } from './shell/UserSettings';
import { isDarkTheme } from './shell/theme';
import './styles.css';

// Pages shown without a session.
const LoginPage = lazy(() => import('./pages/auth/AuthPages').then(m => ({ default: m.LoginPage })));
const LogoffPage = lazy(() => import('./pages/auth/AuthPages').then(m => ({ default: m.LogoffPage })));

// Old full-screen addresses (bookmarks, links in exported reports) open
// the matching page.
function fullscreenTarget(path: string): string {
  const p = path.replace(/^\/fullscreen/, '');
  let m = /^\/notebooks\/([^/]+)/.exec(p);
  if (m) return `/notebooks/${m[1]}`;
  m = /^\/hunts\/([^/]+)\/notebook/.exec(p);
  if (m) return `/hunts/${m[1]}/notebook`;
  m = /^\/collected\/([^/]+)\/([^/]+)\/notebook/.exec(p);
  if (m) return `/collected/${m[1]}/${m[2]}/notebook`;
  m = /^\/shell\/[^/]+\/([^/]+)\//.exec(p);
  if (m) return `/host/${m[1]}/shell`;
  return '/';
}

function Shell() {
  return (
    <UserSettings>
      <Hotkeys />
      <Switch>
        <Route path="/fullscreen" render={({ location }) => <Redirect to={fullscreenTarget(location.pathname)} />} />
        <Route path="/notebooks/:notebook_id/:rest+" render={({ match }) => <Redirect to={`/notebooks/${match.params.notebook_id}`} />} />
        <Route>
          <AppShell />
        </Route>
      </Switch>
    </UserSettings>
  );
}

export default function Root() {
  const errorState = window.ErrorState;
  if (errorState && (errorState.Type === 'Login' || errorState.Type === 'Logoff')) {
    return (
      <Suspense fallback={null}>
        {errorState.Type === 'Login' ? <LoginPage /> : <LogoffPage />}
      </Suspense>
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={300}>
        <HashRouter>
          <ClientProvider>
            <Shell />
          </ClientProvider>
        </HashRouter>
        <Toaster position="bottom-right" theme={isDarkTheme(undefined) ? 'dark' : 'light'} richColors closeButton
          toastOptions={{ className: 'rx' }} />
      </TooltipProvider>
    </QueryClientProvider>
  );
}
