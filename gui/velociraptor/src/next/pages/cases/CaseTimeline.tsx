import { useState } from 'react';
import { toast } from 'sonner';
import { History, Send } from 'lucide-react';
import { fmtTime, timeAgo } from '../../lib/format';
import { Button, Card, CardHeader, Textarea, Tooltip, cn } from '../../ui/primitives';
import type { CaseRecord, EntryKind } from './model';

const KIND_LABEL: Record<EntryKind, string> = {
  created: 'Opened', note: 'Note', status: 'Status', severity: 'Severity', owner: 'Owner',
  link: 'Linked', unlink: 'Unlinked', summary: 'Summary',
};

export function CaseTimeline({ record, onAddNote }: { record: CaseRecord; onAddNote: (text: string) => Promise<unknown> }) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const entries = [...record.timeline].sort((a, b) => b.at - a.at);

  const add = async () => {
    if (!note.trim()) return;
    setBusy(true);
    try {
      await onAddNote(note.trim());
      setNote('');
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader icon={<History className="tw:size-4" />} title="Timeline" subtitle="Notes and every change to the case, newest first" />
      <div className="tw:px-4 tw:pb-3 tw:space-y-2">
        <Textarea rows={3} value={note} onChange={e => setNote(e.target.value)} placeholder="Add a note: findings, decisions, next steps"
          onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) add(); }} />
        <div className="tw:flex tw:justify-end">
          <Button size="sm" variant="primary" icon={<Send className="tw:size-3.5" />} loading={busy} disabled={!note.trim()} onClick={add}>
            Add note
          </Button>
        </div>
      </div>
      <ol className="tw:border-t tw:border-line tw:divide-y tw:divide-line">
        {entries.map(e => (
          <li key={e.id} className="tw:flex tw:gap-3 tw:px-4 tw:py-2.5">
            <span className={cn('tw:mt-1.5 tw:size-2 tw:shrink-0 tw:rounded-full', e.kind === 'note' ? 'tw:bg-accent' : 'tw:bg-line-strong')} />
            <div className="tw:min-w-0 tw:flex-1">
              <div className="tw:flex tw:items-center tw:gap-2 tw:text-2xs tw:text-faint">
                <span className="tw:font-medium tw:text-muted">{KIND_LABEL[e.kind] ?? e.kind}</span>
                <span>{e.by}</span>
                <Tooltip content={fmtTime(new Date(e.at))}><span>{timeAgo(new Date(e.at))}</span></Tooltip>
              </div>
              <div className={cn('tw:text-xs tw:whitespace-pre-wrap tw:break-words', e.kind === 'note' ? 'tw:text-fg' : 'tw:text-muted')}>{e.text}</div>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}
