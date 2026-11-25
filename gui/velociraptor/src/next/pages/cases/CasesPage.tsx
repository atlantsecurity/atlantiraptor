// Cases: group alerts, hunts, collections, hosts and notes into one
// investigation with an owner, status and timeline.
import { useMemo, useState } from 'react';
import { useHistory, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Briefcase, Plus } from 'lucide-react';
import { timeAgo } from '../../lib/format';
import {
  Badge, Button, Card, Dialog, EmptyState, Input, Segmented, Select, Skeleton, Textarea,
} from '../../ui/primitives';
import { CaseDetail } from './CaseDetail';
import { useCases, useCreateCase } from './hooks';
import {
  CASE_SEVERITIES, SEVERITY_TONE, STATUS_LABEL, STATUS_TONE, type CaseSeverity, type CaseStatus,
} from './model';

type Filter = 'active' | CaseStatus | 'all';

export default function CasesPage() {
  const { case_id: caseId } = useParams<{ case_id?: string }>();
  if (caseId) return <CaseDetail id={caseId} />;
  return <CaseList />;
}

function CaseList() {
  const history = useHistory();
  const { cases, isLoading } = useCases();
  const [filter, setFilter] = useState<Filter>('active');
  const [creating, setCreating] = useState(false);
  const shown = useMemo(() => cases.filter(c =>
    filter === 'all' ? true : filter === 'active' ? c.status !== 'closed' : c.status === filter), [cases, filter]);

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <header className="tw:flex tw:flex-wrap tw:items-center tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold">Cases</h1>
            <p className="tw:text-[13px] tw:text-muted">Track an investigation from first alert to closure, with everything linked in one place.</p>
          </div>
          <Segmented value={filter} onChange={v => setFilter(v as Filter)}
            options={[{ value: 'active', label: 'Active' }, { value: 'open', label: 'Open' },
              { value: 'in_progress', label: 'In progress' }, { value: 'closed', label: 'Closed' }, { value: 'all', label: 'All' }]} />
          <Button variant="primary" icon={<Plus className="tw:size-3.5" />} onClick={() => setCreating(true)}>New case</Button>
        </header>

        <Card>
          {isLoading ? (
            <div className="tw:p-4 tw:space-y-3">{[0, 1, 2].map(i => <Skeleton key={i} className="tw:h-10" />)}</div>
          ) : shown.length === 0 ? (
            <EmptyState icon={<Briefcase />} title={cases.length ? 'No cases match this filter' : 'No cases yet'}
              action={<Button size="sm" variant="primary" onClick={() => setCreating(true)}>Open a case</Button>}>
              Open a case from here, or use “Add to case” on an alert.
            </EmptyState>
          ) : (
            <div className="tw:divide-y tw:divide-line">
              {shown.map(c => (
                <button key={c.id} type="button" onClick={() => history.push(`/cases/${c.id}`)}
                  className="tw:flex tw:w-full tw:flex-wrap tw:items-center tw:gap-x-4 tw:gap-y-1 tw:px-4 tw:py-3 tw:text-left tw:hover:bg-hover">
                  <div className="tw:min-w-0 tw:flex-1 tw:basis-64">
                    <div className="tw:text-[13px] tw:font-medium tw:truncate">{c.title}</div>
                    <div className="tw:text-2xs tw:text-faint tw:truncate">
                      {c.id} · {c.links.length} linked · owner {c.owner || 'unassigned'} · updated {timeAgo(new Date(c.modified))}
                    </div>
                  </div>
                  <Badge tone={SEVERITY_TONE[c.severity]} className="tw:capitalize">{c.severity}</Badge>
                  <Badge tone={STATUS_TONE[c.status]} dot>{STATUS_LABEL[c.status]}</Badge>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>
      {creating && <NewCaseDialog onClose={() => setCreating(false)} onCreated={id => history.push(`/cases/${id}`)} />}
    </div>
  );
}

export function NewCaseDialog({ onClose, onCreated, initialTitle = '', initialSeverity = 'medium' }: {
  onClose: () => void; onCreated: (id: string) => void; initialTitle?: string; initialSeverity?: CaseSeverity;
}) {
  const create = useCreateCase();
  const [title, setTitle] = useState(initialTitle);
  const [severity, setSeverity] = useState<CaseSeverity>(initialSeverity);
  const [summary, setSummary] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!title.trim()) return;
    setBusy(true);
    try {
      const id = await create({ title: title.trim(), severity, summary });
      toast.success('Case opened');
      onCreated(id);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={v => !v && onClose()} title="New case"
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={busy} disabled={!title.trim()} onClick={submit}>Open case</Button>
      </>}>
      <div className="tw:space-y-3">
        <label className="tw:block">
          <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Title</span>
          <Input autoFocus value={title} onChange={e => setTitle(e.target.value)} placeholder="e.g. Suspicious service on FINANCE-07" />
        </label>
        <label className="tw:block tw:max-w-[200px]">
          <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Severity</span>
          <Select value={severity} onChange={e => setSeverity(e.target.value as CaseSeverity)}>
            {CASE_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
        </label>
        <label className="tw:block">
          <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Summary (optional)</span>
          <Textarea rows={3} value={summary} onChange={e => setSummary(e.target.value)} placeholder="What happened and what you know so far" />
        </label>
      </div>
    </Dialog>
  );
}
