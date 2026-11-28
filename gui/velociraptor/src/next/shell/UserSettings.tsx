// Keeps the signed-in user's settings ("traits": name, orgs, theme,
// timezone, permissions) fresh for the whole console, and makes sure
// the page address names the org it shows.
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useHistory } from 'react-router-dom';
import qs from 'qs';
import * as api from '../lib/api';
import type { UserTraits } from '../lib/types';

export interface UserConfigValue {
  traits: UserTraits;
  updateTraits: () => void;
  messages?: number;
}

export const UserConfig = React.createContext<UserConfigValue>({ traits: {} as UserTraits, updateTraits: () => {} });

const POLL_MS = 5000;

interface TraitsResponse {
  interface_traits?: UserTraits & { org?: string; auth_redirect_template?: string; lang?: string };
  username?: string;
  orgs?: UserTraits['orgs'];
  messages?: number;
}

export function UserSettings({ children }: { children: React.ReactNode }) {
  const history = useHistory();
  const [value, setValue] = useState<Omit<UserConfigValue, 'updateTraits'>>({ traits: {} as UserTraits, messages: 0 });
  const inflight = useRef<AbortController | null>(null);

  const updateTraits = useCallback(() => {
    inflight.current?.abort();
    const ctl = new AbortController();
    inflight.current = ctl;
    api.get<TraitsResponse>('v1/GetUserUITraits', {}, ctl.signal).then(resp => {
      const traits = resp.interface_traits;
      if (!traits) return;
      if (traits.lang) window.globals.lang = traits.lang;
      if (traits.org) {
        // The org in the address wins; without one, use the user's default
        // and put it in the address, keeping the page a link pointed at.
        const params = qs.parse(window.location.search.replace(/^\?/, ''));
        window.globals.OrgId = (params.org_id as string) || traits.org;
        if (!params.org_id) {
          const hash = window.location.hash || '';
          window.history.replaceState({}, '', api.href('/app/index.html', {}) + hash);
          if (!hash || hash === '#/' || hash === '#') history.replace('/welcome');
        }
      }
      if (traits.auth_redirect_template) window.globals.AuthRedirectTemplate = traits.auth_redirect_template;
      setValue({ traits: { ...traits, username: resp.username, orgs: resp.orgs }, messages: resp.messages ?? 0 });
    }).catch(() => { /* keep the last known traits; the next poll retries */ });
  }, [history]);

  useEffect(() => {
    updateTraits();
    const t = setInterval(updateTraits, POLL_MS);
    return () => { clearInterval(t); inflight.current?.abort(); };
  }, [updateTraits]);

  return <UserConfig.Provider value={{ ...value, updateTraits }}>{children}</UserConfig.Provider>;
}
