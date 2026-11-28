// Sign-in and signed-out pages. The server renders these when there is
// no session (window.ErrorState says which, and lists the sign-in
// providers configured for single sign-on).
import { LogIn } from 'lucide-react';
import * as api from '../../lib/api';
import logo from '../../assets/atlantiraptor.svg';
import github from '../../assets/login/github.svg';
import google from '../../assets/login/google.svg';
import microsoft from '../../assets/login/microsoft.svg';
import openid from '../../assets/login/openid.svg';

interface Provider { ProviderName?: string; ProviderAvatar?: string; LoginURL?: string }

function providerIcon(p: Provider): string {
  switch (p.ProviderName) {
    case 'Google': return api.srcOf(google);
    case 'Github': return api.srcOf(github);
    case 'Microsoft': return api.srcOf(microsoft);
    default: return p.ProviderAvatar || api.srcOf(openid);
  }
}

function AuthFrame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rx tw:min-h-screen tw:flex tw:items-center tw:justify-center tw:bg-canvas tw:p-4">
      <div className="tw:w-full tw:max-w-[420px] tw:rounded-xl tw:border tw:border-line tw:bg-panel rx-shadow-lg tw:p-6 tw:space-y-5">
        <div className="tw:flex tw:items-center tw:gap-3">
          <img src={api.srcOf(logo)} alt="" className="tw:size-9" />
          <div>
            <div className="tw:text-[15px] tw:font-semibold">Atlantiraptor</div>
            <div className="tw:text-xs tw:text-muted">{title}</div>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}

export function LoginPage() {
  const state = window.ErrorState ?? { Type: 'Login' };
  const providers = (state.Authenticators as Provider[] | undefined) ?? [];
  const username = state.Username as string | undefined;
  return (
    <AuthFrame title="Sign in">
      {username && (
        <div className="tw:rounded-md tw:border tw:border-warn/40 tw:bg-warn-soft tw:p-3 tw:text-xs tw:text-warn">
          <span className="tw:font-medium">{username}</span> is not a user of this server. Ask your administrator to add you, or sign in with another account.
        </div>
      )}
      <div className="tw:space-y-2">
        {providers.length === 0 && <div className="tw:text-xs tw:text-muted">No sign-in method is configured.</div>}
        {providers.map(p => (
          <a key={`${p.ProviderName}-${p.LoginURL}`} href={api.href(p.LoginURL ?? '/')}
            className="tw:flex tw:items-center tw:gap-3 tw:h-11 tw:px-3 tw:rounded-lg tw:border tw:border-line tw:text-[13px] tw:font-medium tw:text-fg tw:no-underline tw:hover:bg-hover tw:hover:border-accent">
            <img src={providerIcon(p)} alt="" className="tw:size-5" />
            Sign in with {p.ProviderName || 'single sign-on'}
          </a>
        ))}
      </div>
    </AuthFrame>
  );
}

export function LogoffPage() {
  const username = window.ErrorState?.Username as string | undefined;
  return (
    <AuthFrame title="Signed out">
      <p className="tw:text-[13px]">{username ? <><span className="tw:font-medium">{username}</span> is now signed out.</> : 'You are now signed out.'}</p>
      <a href={api.basePath() || '/'}
        className="tw:inline-flex tw:items-center tw:gap-2 tw:h-9 tw:px-3 tw:rounded-lg tw:bg-accent tw:text-white tw:text-[13px] tw:font-medium tw:no-underline tw:hover:opacity-90">
        <LogIn className="tw:size-4" />Sign in again
      </a>
    </AuthFrame>
  );
}
