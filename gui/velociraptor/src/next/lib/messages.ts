// The signed in user's console messages (/api/v1/atl/messages):
// security advisories, announcements and messages from other users.
// The server groups identical deliveries and keeps read/dismissed state.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as api from './api';

export type Severity = 'critical' | 'warning' | 'info';
export type Category = 'security' | 'announcement' | 'message';

export interface UserMessage {
  id: string;
  title: string;
  summary?: string;
  link?: string;
  link_host?: string;
  published?: number;
  from: string;
  from_user: boolean;
  severity: Severity;
  category: Category;
  cves?: string[];
  fields?: { key: string; value: string }[];
  raw: string;
  first_seen: number;
  last_seen: number;
  count: number;
  read: boolean;
  dismissed: boolean;
}

export interface MessagesSummary {
  items: UserMessage[];
  unread: number;
  total: number;
  dismissed: number;
}

export type MessageAction =
  | { action: 'read' | 'unread' | 'dismiss' | 'restore'; ids: string[] }
  | { action: 'clear' };

export const ALL = '*';

const key = (dismissed: boolean) => ['user-messages', { dismissed }];

export function useMessages(dismissed = false) {
  return useQuery({
    queryKey: key(dismissed),
    queryFn: ({ signal }) => api.get<MessagesSummary>('v1/atl/messages', dismissed ? { dismissed: 1 } : {}, signal),
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  });
}

export function useMessageAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: MessageAction) => api.post<MessagesSummary>('v1/atl/messages', p),
    // Apply the change at once so the list does not flicker.
    onMutate: async p => {
      await qc.cancelQueries({ queryKey: ['user-messages'] });
      const ids = 'ids' in p ? new Set(p.ids) : null;
      const hit = (m: UserMessage) => !!ids && (ids.has(ALL) || ids.has(m.id));
      qc.setQueriesData<MessagesSummary>({ queryKey: ['user-messages'] }, old => {
        if (!old) return old;
        if (p.action === 'clear') return { items: [], unread: 0, total: 0, dismissed: 0 };
        const items = old.items.map(m => {
          if (!hit(m)) return m;
          switch (p.action) {
            case 'read': return { ...m, read: true };
            case 'unread': return { ...m, read: false };
            case 'dismiss': return { ...m, dismissed: true };
            case 'restore': return { ...m, dismissed: false };
          }
          return m;
        });
        const live = items.filter(m => !m.dismissed);
        return { ...old, items, total: live.length, unread: live.filter(m => !m.read).length };
      });
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ['user-messages'] }),
  });
}

export const CATEGORY_LABEL: Record<Category, string> = {
  security: 'Security advisory',
  announcement: 'Announcement',
  message: 'Message',
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  warning: 'Important',
  info: 'Info',
};
