// The Server settings section: one place for the administration pages.
// Pages keep their own addresses (so old links and bookmarks still
// work); this list groups them and drives the section's navigation.

export interface SettingsPage {
  id: string;
  to: string;
  label: string;
  description: string;
  match: RegExp;
  keys: string;
}

export interface SettingsGroup {
  title: string;
  pages: SettingsPage[];
}

export const SETTINGS_GROUPS: SettingsGroup[] = [
  {
    title: 'People and access',
    pages: [
      { id: 'users', to: '/users', label: 'Users', match: /^\/users(\/|$)/, keys: 'accounts roles admin',
        description: 'Console accounts and the roles each one has.' },
      { id: 'groups', to: '/groups', label: 'Groups', match: /^\/groups(\/|$)/, keys: 'teams roles',
        description: 'Give roles to many users at once.' },
      { id: 'orgs', to: '/orgs', label: 'Organizations', match: /^\/orgs(\/|$)/, keys: 'orgs tenants customers multi-tenancy',
        description: 'Separate tenants on one server, and who can use each.' },
      { id: 'security', to: '/account/security', label: 'Security and 2FA', match: /^\/account(\/|$)/, keys: 'mfa totp password policy two-factor',
        description: 'Two-factor sign-in and the password policy.' },
    ],
  },
  {
    title: 'Server',
    pages: [
      { id: 'https', to: '/settings/https', label: 'Address and certificate', match: /^\/settings\/https(\/|$)/,
        keys: 'https ssl tls certificate domain hostname lets encrypt 443 url port',
        description: 'Serve the console at your own host name, with a certificate browsers trust.' },
      { id: 'network', to: '/network', label: 'Network access', match: /^\/network(\/|$)/, keys: 'allowlist ip cidr firewall',
        description: 'Which addresses may reach the console and the API.' },
      { id: 'deploy', to: '/settings/deploy', label: 'Deploy a client', match: /^\/settings\/deploy(\/|$)/, keys: 'install agent msi intune endpoint',
        description: 'Installers and the Intune package for endpoints.' },
      { id: 'updates', to: '/updates', label: 'Server updates', match: /^\/updates(\/|$)/, keys: 'upgrade version release',
        description: 'Install new Atlantiraptor releases.' },
    ],
  },
  {
    title: 'Integrations',
    pages: [
      { id: 'integrations', to: '/integrations', label: 'Integrations', match: /^\/integrations(\/|$)/, keys: 'email teams slack ai threat intel',
        description: 'Email, chat, AI and threat intelligence connections.' },
      { id: 'apikeys', to: '/apikeys', label: 'API keys', match: /^\/apikeys(\/|$)/, keys: 'siem soar rest token',
        description: 'Keys for SIEM and SOAR tools that use the REST API.' },
      { id: 'secrets', to: '/secrets', label: 'Secrets', match: /^\/secrets(\/|$)/, keys: 'credentials passwords tokens',
        description: 'Credentials that artifacts and cloud hunts use.' },
    ],
  },
];

export const SETTINGS_PAGES: SettingsPage[] = SETTINGS_GROUPS.flatMap(g => g.pages);

// Is this address one of the settings pages (or the overview)?
export function isSettingsPath(pathname: string): boolean {
  return pathname === '/settings' || pathname.startsWith('/settings/') ||
    SETTINGS_PAGES.some(p => p.match.test(pathname));
}

export function activeSettingsPage(pathname: string): SettingsPage | undefined {
  return SETTINGS_PAGES.find(p => p.match.test(pathname));
}
