// Messages: security advisories, announcements and messages from other
// users, as an inbox. The server groups identical deliveries (the same
// advisory sent once per org shows once, with a count) and keeps the
// read and dismissed state per user.
import { useEffect, useMemo, useState } from 'react';
import { useHistory, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Archive, ArchiveRestore, Bell, CheckCheck, ExternalLink, Mail, MailOpen, Trash2,
} from 'lucide-react';
import { SeverityIcon } from '../../ui/MessageIcon';
import {
  ALL, CATEGORY_LABEL, SEVERITY_LABEL, useMessageAction, useMessages, type Category, type UserMessage,
} from '../../lib/messages';
import { timeAgo } from '../../lib/format';
import {
  Badge, Button, cn, ConfirmDialog, CopyButton, EmptyState, Mono, SearchInput, Segmented, Skeleton, Switch,
} from '../../ui/primitives';
import { MobileBack } from '../../ui/MobileBack';

type Filter = 'all' | 'unread' | Category;

const when = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleString() : '');
const day = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' }) : '');

export function SeverityBadge({ m }: { m: UserMessage }) {
  const tone = m.severity === 'critical' ? 'bad' : m.severity === 'warning' ? 'warn' : 'info';
  return <Badge tone={tone}>{SEVERITY_LABEL[m.severity]}</Badge>;
}

export function sender(m: UserMessage) {
  return m.from_user ? m.from : 'This server';
}

export default function MessagesPage() {
  const { id } = useParams<{ id?: string }>();
  const history = useHistory();
  const [showDismissed, setShowDismissed] = useState(false);
  const { data, isLoading, error } = useMessages(showDismissed);
  const act = useMessageAction();
  const [filter, setFilter] = useState<Filter>('all');
  const [q, setQ] = useState('');
  const [confirmClear, setConfirmClear] = useState(false);

  const items = useMemo(() => data?.items ?? [], [data]);
  const counts = useMemo(() => {
    const live = items.filter(m => !m.dismissed);
    return {
      all: live.length,
      unread: live.filter(m => !m.read).length,
      security: live.filter(m => m.category === 'security').length,
      announcement: live.filter(m => m.category === 'announcement').length,
      message: live.filter(m => m.category === 'message').length,
    };
  }, [items]);

  const shown = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return items.filter(m => {
      if (filter === 'unread' && (m.read || m.dismissed)) return false;
      if (filter !== 'all' && filter !== 'unread' && m.category !== filter) return false;
      if (!ql) return true;
      return `${m.title} ${m.summary ?? ''} ${m.from} ${m.link ?? ''} ${(m.cves ?? []).join(' ')}`.toLowerCase().includes(ql);
    });
  }, [items, filter, q]);

  const selected = items.find(m => m.id === id);

  // Opening a message marks it read.
  useEffect(() => {
    if (selected && !selected.read && !selected.dismissed && !act.isPending) {
      act.mutate({ action: 'read', ids: [selected.id] });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id, selected?.read]);

  const open = (m: UserMessage) => history.push(`/messages/${m.id}`);
  const run = (p: Parameters<typeof act.mutate>[0], done?: string) =>
    act.mutate(p, {
      onSuccess: () => done && toast.success(done),
      onError: e => toast.error((e as Error).message),
    });

  const dismiss = (m: UserMessage) => {
    // Move to the next message so you can work down the list.
    const idx = shown.findIndex(x => x.id === m.id);
    const next = shown[idx + 1] ?? shown[idx - 1];
    run({ action: 'dismiss', ids: [m.id] });
    if (!showDismissed) history.replace(next && next.id !== m.id ? `/messages/${next.id}` : '/messages');
  };

  if (isLoading) return <div className="tw:p-6 tw:space-y-2"><Skeleton className="tw:h-10" /><Skeleton className="tw:h-64" /></div>;
  if (error || !data) {
    return <EmptyState icon={<Bell />} title="Messages are not available">{(error as Error)?.message}</EmptyState>;
  }

  return (
    <div className="tw:flex tw:flex-col tw:flex-1 tw:min-h-0 tw:bg-canvas">
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:px-3 tw:md:px-4 tw:py-2.5 tw:border-b tw:border-line tw:bg-panel">
        <h1 className="tw:text-base tw:font-semibold tw:flex tw:items-center tw:gap-2 tw:mr-2">
          <Bell className="tw:size-4 tw:text-accent" />Messages
          {data.unread > 0 && <Badge tone="bad">{data.unread} unread</Badge>}
        </h1>
        <div className="tw:overflow-x-auto tw:max-w-full tw:[&_button]:whitespace-nowrap">
          <Segmented<Filter> value={filter} onChange={setFilter} options={[
            { value: 'all', label: 'All', count: counts.all },
            { value: 'unread', label: 'Unread', count: counts.unread },
            { value: 'security', label: 'Security', count: counts.security },
            { value: 'announcement', label: 'Announcements', count: counts.announcement },
            { value: 'message', label: 'From users', count: counts.message },
          ]} />
        </div>
        <div className="tw:ml-auto tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <Switch checked={showDismissed} onChange={setShowDismissed}
            label={`Show dismissed${data.dismissed ? ` (${data.dismissed})` : ''}`} />
          <Button size="sm" icon={<CheckCheck className="tw:size-3.5" />} disabled={!data.unread}
            onClick={() => run({ action: 'read', ids: [ALL] }, 'All messages marked as read')}>Mark all read</Button>
          <Button size="sm" variant="ghost" icon={<Trash2 className="tw:size-3.5" />} disabled={!items.length}
            onClick={() => setConfirmClear(true)}>Delete all</Button>
        </div>
      </div>

      <div className="rx-split tw:flex tw:flex-1 tw:min-h-0" data-detail={selected ? 1 : 0}>
        <aside className="rx-split-list tw:w-[400px] tw:shrink-0 tw:border-r tw:border-line tw:flex tw:flex-col tw:bg-panel">
          <div className="tw:p-2 tw:border-b tw:border-line">
            <SearchInput value={q} onChange={setQ} placeholder="Search messages, CVE ids, senders…" />
          </div>
          <div className="tw:flex-1 tw:overflow-y-auto" role="list">
            {shown.length === 0 && (
              <EmptyState icon={<MailOpen />} title={items.length ? 'Nothing matches' : 'No messages'}>
                {items.length ? 'Try another filter or search.'
                  : 'Security advisories, announcements and messages from other users appear here.'}
              </EmptyState>
            )}
            {shown.map(m => (
              <button key={m.id} type="button" role="listitem" onClick={() => open(m)}
                className={cn('tw:w-full tw:text-left tw:flex tw:gap-2.5 tw:px-3 tw:py-2.5 tw:border-b tw:border-line tw:hover:bg-hover',
                  m.id === id && 'tw:bg-accent-soft tw:hover:bg-accent-soft', m.dismissed && 'tw:opacity-60')}>
                <span className="tw:pt-0.5 tw:flex tw:flex-col tw:items-center tw:gap-1.5">
                  <SeverityIcon m={m} />
                  {!m.read && !m.dismissed && <span className="tw:size-2 tw:rounded-full tw:bg-accent" aria-label="Unread" />}
                </span>
                <span className="tw:min-w-0 tw:flex-1">
                  <span className={cn('tw:block tw:text-[13px] tw:leading-snug tw:break-words', !m.read && !m.dismissed ? 'tw:font-semibold' : 'tw:text-muted')}>
                    {m.title}
                  </span>
                  <span className="tw:mt-1 tw:flex tw:flex-wrap tw:items-center tw:gap-x-2 tw:gap-y-1 tw:text-2xs tw:text-faint">
                    <span>{CATEGORY_LABEL[m.category]}</span>
                    {m.link_host && <span className="tw:truncate tw:max-w-[160px]">{m.link_host}</span>}
                    {m.from_user && <span>from {m.from}</span>}
                    {m.count > 1 && <span title="Delivered more than once">×{m.count}</span>}
                    {m.dismissed && <span>dismissed</span>}
                    <span className="tw:ml-auto" title={when(m.last_seen)}>{timeAgo(m.last_seen)}</span>
                  </span>
                </span>
              </button>
            ))}
          </div>
        </aside>

        <main className="rx-split-detail tw:flex-1 tw:min-w-0 tw:overflow-y-auto">
          {selected ? <MobileBack to="/messages" label="Messages" /> : null}
          {selected ? (
            <MessageDetail m={selected}
              onDismiss={() => dismiss(selected)}
              onRestore={() => run({ action: 'restore', ids: [selected.id] }, 'Message restored')}
              onUnread={() => { run({ action: 'unread', ids: [selected.id] }); history.push('/messages'); }} />
          ) : (
            <EmptyState icon={<Mail />} title={id ? 'This message is gone' : 'Select a message'} className="tw:h-full">
              {id ? 'It was deleted, or dismissed (turn on Show dismissed to see it).' : 'Pick a message on the left to read all of it.'}
            </EmptyState>
          )}
        </main>
      </div>

      <ConfirmDialog open={confirmClear} onOpenChange={setConfirmClear} title="Delete all messages?" danger
        confirmLabel="Delete all" loading={act.isPending}
        onConfirm={() => run({ action: 'clear' }, 'All messages deleted')}>
        This deletes every message in your inbox, including dismissed ones. Other users keep theirs.
        New advisories still arrive. To hide messages but keep them, dismiss them instead.
      </ConfirmDialog>
    </div>
  );
}

function MessageDetail({ m, onDismiss, onRestore, onUnread }: {
  m: UserMessage; onDismiss: () => void; onRestore: () => void; onUnread: () => void;
}) {
  const [raw, setRaw] = useState(false);
  return (
    <article className="tw:p-4 tw:md:p-6 tw:max-w-3xl tw:space-y-5">
      <header className="tw:space-y-3">
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5">
          <SeverityIcon m={m} />
          <Badge tone={m.category === 'security' ? 'bad' : m.category === 'message' ? 'accent' : 'info'}>{CATEGORY_LABEL[m.category]}</Badge>
          <SeverityBadge m={m} />
          {(m.cves ?? []).map(c => <Badge key={c} tone="neutral" className="tw:font-mono">{c}</Badge>)}
          {m.dismissed && <Badge>Dismissed</Badge>}
        </div>
        <h2 className="tw:text-lg tw:md:text-xl tw:font-semibold tw:leading-snug tw:break-words">{m.title}</h2>
        <div className="tw:text-xs tw:text-muted tw:flex tw:flex-wrap tw:gap-x-4 tw:gap-y-1">
          <span>From <span className="tw:text-fg">{sender(m)}</span></span>
          {m.published ? <span>Published {day(m.published)}</span> : null}
          <span title={when(m.last_seen)}>Received {timeAgo(m.last_seen)}</span>
          {m.count > 1 && <span>Delivered {m.count} times since {when(m.first_seen)}</span>}
        </div>
      </header>

      {m.link && (
        <div className="tw:rounded-lg tw:border tw:border-line tw:bg-panel tw:p-3 tw:flex tw:flex-wrap tw:items-center tw:gap-3">
          <a href={m.link} target="_blank" rel="noopener noreferrer"
            className="tw:inline-flex tw:items-center tw:gap-1.5 tw:h-8 tw:px-3 tw:rounded-md tw:bg-accent tw:text-accent-fg tw:text-[13px] tw:font-medium tw:hover:opacity-90 tw:no-underline">
            <ExternalLink className="tw:size-3.5" />
            {m.category === 'security' ? 'Read the advisory' : 'Open link'}
          </a>
          <a href={m.link} target="_blank" rel="noopener noreferrer"
            className="tw:min-w-0 tw:flex-1 tw:text-xs tw:text-accent tw:break-all tw:hover:underline">{m.link}</a>
          <CopyButton text={m.link} />
          {m.from_user && <p className="tw:w-full tw:text-2xs tw:text-faint">Sent by a user of this server. Check the address before you open it.</p>}
        </div>
      )}

      {m.summary && <div className="tw:text-[13px] tw:leading-relaxed tw:whitespace-pre-wrap tw:break-words">{m.summary}</div>}

      {m.category === 'security' && (
        <div className="tw:rounded-lg tw:border tw:border-line tw:bg-panel tw:p-3 tw:text-xs tw:text-muted tw:space-y-1">
          <div className="tw:font-medium tw:text-fg">What to do</div>
          <p>Read the advisory, then check that this server runs a version with the fix under Admin &gt; Server updates.
            Atlantiraptor releases carry the upstream security fixes and the server installs them by itself when automatic updates are on.</p>
          <a href="#/updates" className="tw:text-accent tw:hover:underline">Open Server updates</a>
        </div>
      )}

      {(m.fields?.length ?? 0) > 0 && (
        <dl className="tw:rounded-lg tw:border tw:border-line tw:bg-panel tw:divide-y tw:divide-line tw:text-[13px]">
          {m.fields!.map(f => (
            <div key={f.key} className="tw:grid tw:grid-cols-[minmax(90px,160px)_1fr] tw:gap-3 tw:px-3 tw:py-2">
              <dt className="tw:text-muted tw:break-words">{f.key}</dt>
              <dd className="tw:break-words tw:whitespace-pre-wrap tw:min-w-0">{f.value}</dd>
            </div>
          ))}
        </dl>
      )}

      <div className="tw:flex tw:flex-wrap tw:gap-2 tw:pt-1">
        {m.dismissed
          ? <Button icon={<ArchiveRestore className="tw:size-3.5" />} onClick={onRestore}>Restore</Button>
          : <Button icon={<Archive className="tw:size-3.5" />} onClick={onDismiss}>Dismiss</Button>}
        {!m.dismissed && <Button variant="ghost" icon={<Mail className="tw:size-3.5" />} onClick={onUnread}>Mark unread</Button>}
        <Button variant="ghost" onClick={() => setRaw(r => !r)}>{raw ? 'Hide' : 'Show'} original message</Button>
      </div>

      {raw && (
        <div className="tw:relative">
          <pre className="tw:rounded-lg tw:border tw:border-line tw:bg-panel tw:p-3 tw:text-[12px] tw:whitespace-pre-wrap tw:break-all"><Mono>{m.raw}</Mono></pre>
          <div className="tw:absolute tw:top-2 tw:right-2"><CopyButton text={m.raw} /></div>
        </div>
      )}
    </article>
  );
}
