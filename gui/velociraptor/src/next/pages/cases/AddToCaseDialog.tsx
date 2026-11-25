// Adds an item (alert, hunt, collection, host) to an existing case or to
// a new one opened on the spot.
import { useState } from 'react';
import { useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import { Briefcase, Plus } from 'lucide-react';
import { Badge, Button, Dialog, Skeleton } from '../../ui/primitives';
import { NewCaseDialog } from './CasesPage';
import { useCases, useLinkToCase, type NewLink } from './hooks';
import { STATUS_LABEL, STATUS_TONE, type CaseSeverity } from './model';

export function AddToCaseDialog({ item, suggestedTitle, suggestedSeverity, onClose }: {
  item: NewLink; suggestedTitle: string; suggestedSeverity?: CaseSeverity; onClose: () => void;
}) {
  const history = useHistory();
  const { cases, isLoading } = useCases();
  const link = useLinkToCase();
  const [busy, setBusy] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const active = cases.filter(c => c.status !== 'closed');

  const add = async (caseId: string) => {
    setBusy(caseId);
    try {
      await link(caseId, item);
      toast.success('Added to case', { action: { label: 'Open', onClick: () => history.push(`/cases/${caseId}`) } });
      onClose();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  if (creating) {
    return <NewCaseDialog initialTitle={suggestedTitle} initialSeverity={suggestedSeverity}
      onClose={() => setCreating(false)} onCreated={id => add(id)} />;
  }

  return (
    <Dialog open onOpenChange={v => !v && onClose()} title="Add to case" description={item.label}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" icon={<Plus className="tw:size-3.5" />} onClick={() => setCreating(true)}>New case</Button>
      </>}>
      {isLoading ? <Skeleton className="tw:h-24" /> : active.length === 0 ? (
        <div className="tw:text-xs tw:text-muted tw:py-4 tw:text-center">No open cases. Start a new one.</div>
      ) : (
        <div className="tw:max-h-80 tw:overflow-y-auto tw:divide-y tw:divide-line tw:rounded-md tw:border tw:border-line">
          {active.map(c => (
            <button key={c.id} type="button" disabled={!!busy} onClick={() => add(c.id)}
              className="tw:flex tw:w-full tw:items-center tw:gap-2.5 tw:px-3 tw:py-2 tw:text-left tw:hover:bg-hover tw:disabled:opacity-50">
              <Briefcase className="tw:size-4 tw:text-faint tw:shrink-0" />
              <span className="tw:min-w-0 tw:flex-1 tw:truncate tw:text-[13px]">{c.title}</span>
              <Badge tone={STATUS_TONE[c.status]} dot>{STATUS_LABEL[c.status]}</Badge>
            </button>
          ))}
        </div>
      )}
    </Dialog>
  );
}
