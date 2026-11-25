// Client for two-factor sign in and user groups (server endpoints under
// /api/v1/atl/). Enforcement happens on the server; these only drive the
// screens.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export interface MfaStatus { enrolled: boolean; recovery_codes_left: number }
export interface TotpBegin { secret: string; otpauth_url: string; qr_png: string }
export interface Group { name: string; description?: string; roles: string[]; members: string[] }

export const PASSWORD_RULES = [
  'At least 12 characters',
  'At least three of: lower case, upper case, digits, symbols',
  'Must not contain your user name or a common password',
];

export function passwordProblems(username: string, password: string): string[] {
  const problems: string[] = [];
  if ([...password].length < 12) problems.push('Use at least 12 characters.');
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(re => re.test(password)).length;
  if (classes < 3) problems.push('Mix at least three of: lower case, upper case, digits, symbols.');
  if (username.length >= 3 && password.toLowerCase().includes(username.toLowerCase())) problems.push('Do not include the user name.');
  return problems;
}

export function useMfaStatus() {
  return useQuery({
    queryKey: ['mfa-status'],
    queryFn: ({ signal }) => api.get<MfaStatus>('v1/atl/mfa/manage/status', {}, signal),
  });
}

export function useMfaActions() {
  const qc = useQueryClient();
  const refresh = () => qc.invalidateQueries({ queryKey: ['mfa-status'] });
  return {
    begin: () => api.post<TotpBegin>('v1/atl/mfa/manage/totp/begin', {}),
    confirm: async (code: string) => {
      const r = await api.post<{ recovery_codes: string[] }>('v1/atl/mfa/manage/totp/confirm', { code });
      refresh();
      return r.recovery_codes;
    },
    disable: async (code: string) => {
      await api.post('v1/atl/mfa/manage/disable', { code });
      refresh();
    },
    regenerate: async (code: string) => {
      const r = await api.post<{ recovery_codes: string[] }>('v1/atl/mfa/manage/recovery/regenerate', { code });
      refresh();
      return r.recovery_codes;
    },
  };
}

export function useUserMfaStatus(username: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['mfa-user-status', username],
    enabled: !!username && enabled,
    queryFn: ({ signal }) => api.get<{ username: string; enrolled: boolean }>('v1/atl/mfa/manage/user_status', { username }, signal),
    retry: false,
  });
}

export function useResetUserMfa() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (username: string) => api.post('v1/atl/mfa/manage/admin_reset', { username }),
    onSettled: (_d, _e, username) => qc.invalidateQueries({ queryKey: ['mfa-user-status', username] }),
  });
}

export function useGroups() {
  return useQuery({
    queryKey: ['groups'],
    queryFn: ({ signal }) => api.get<{ groups: Group[] }>('v1/atl/groups', {}, signal),
    select: d => d.groups ?? [],
    retry: false,
  });
}

export function useSaveGroups() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (groups: Group[]) => api.post<{ groups: Group[] }>('v1/atl/groups', { groups }),
    onSuccess: d => qc.setQueryData(['groups'], d),
  });
}
