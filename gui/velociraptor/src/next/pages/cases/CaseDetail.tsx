// One case: status, severity, owner, summary, linked items and timeline.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { ArrowLeft, BookOpen, Briefcase, Download, Save } from 'lucide-react';
import { useGlobalUsers } from '../../lib/queries';
import { Badge, Button, Card, CardHeader, EmptyState, Select, Skeleton, Textarea } from '../../ui/primitives';
import { CaseLinks } from './CaseLinks';
import { CaseTimeline } from './CaseTimeline';
import { useCase, useCaseActions, useMe } from './hooks';
import {
  CASE_SEVERITIES, SEVERITY_TONE, STATUSES, STATUS_LABEL, STATUS_TONE, type CaseSeverity, type CaseStatus,
} from './model';
import { downloadCaseReport } from './report';

export function CaseDetail({ id }: { id: string }) {
  const { notebook, record, isLoading, error } = useCase(id);
  const actions = useCaseActions(id);
  const me = useMe();
  const { data: users = [] } = useGlobalUsers();

  const run = async (p: Promise<unknown>) => {
    try {
      await p;
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  if (isLoading) return <div className="tw:p-6 tw:space-y-3"><Skeleton className="tw:h-8 tw:w-1/3" /><Skeleton className="tw:h-40" /></div>;
  if (!record) {
    return (
      <EmptyState icon={<Briefcase />} title="Case not found"
        action={<Link to="/cases" className="tw:text-xs tw:text-accent tw:hover:underline">Back to cases</Link>}>
        {error ? (error as Error).message : id}
      </EmptyState>
    );
  }

  const owners = Array.from(new Set([record.owner, me, ...users.map(u => u.name)].filter(Boolean)));

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <Link to="/cases" className="tw:inline-flex tw:items-center tw:gap-1 tw:text-xs tw:text-muted tw:hover:text-accent">
          <ArrowLeft className="tw:size-3.5" />Cases
        </Link>
        <header className="tw:flex tw:flex-wrap tw:items-start tw:gap-3">
          <div className="tw:min-w-0 tw:flex-1">
            <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
              <h1 className="tw:text-xl tw:font-semibold">{record.title}</h1>
              <Badge tone={SEVERITY_TONE[record.severity]} className="tw:capitalize">{record.severity}</Badge>
              <Badge tone={STATUS_TONE[record.status]} dot>{STATUS_LABEL[record.status]}</Badge>
            </div>
            <div className="tw:text-2xs tw:text-faint tw:mt-1 tw:font-mono">{id} · opened by {notebook?.creator}</div>
          </div>
          <div className="tw:flex tw:flex-wrap tw:gap-1.5">
            <Link to={`/notebooks/${id}`}>
              <Button size="sm" variant="secondary" icon={<BookOpen className="tw:size-3.5" />}>Open notebook</Button>
            </Link>
            <Button size="sm" variant="secondary" icon={<Download className="tw:size-3.5" />}
              onClick={() => downloadCaseReport(id, record, notebook?.creator ?? '')}>Export report</Button>
          </div>
        </header>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-3 tw:gap-4 tw:items-start">
          <div className="tw:space-y-4 tw:xl:col-span-2">
            <Card>
              <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-3 tw:gap-3 tw:p-4">
                <Field label="Status">
                  <Select value={record.status} onChange={e => run(actions.setStatus(e.target.value as CaseStatus))}>
                    {STATUSES.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                  </Select>
                </Field>
                <Field label="Severity">
                  <Select value={record.severity} onChange={e => run(actions.setSeverity(e.target.value as CaseSeverity))}>
                    {CASE_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                  </Select>
                </Field>
                <Field label="Owner">
                  <Select value={record.owner} onChange={e => run(actions.setOwner(e.target.value))}>
                    <option value="">Unassigned</option>
                    {owners.map(o => <option key={o} value={o}>{o}{o === me ? ' (me)' : ''}</option>)}
                  </Select>
                </Field>
              </div>
              <SummaryEditor key={record.summary} value={record.summary} onSave={v => run(actions.setSummary(v))} />
            </Card>
            <CaseTimeline record={record} onAddNote={text => actions.addNote(text)} />
          </div>
          <CaseLinks caseId={id} record={record} onUnlink={linkId => run(actions.unlink(linkId))} />
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="tw:block">
      <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">{label}</span>
      {children}
    </label>
  );
}

function SummaryEditor({ value, onSave }: { value: string; onSave: (v: string) => void }) {
  const [draft, setDraft] = useState(value);
  return (
    <div className="tw:border-t tw:border-line">
      <CardHeader title="Summary" actions={draft !== value && (
        <Button size="sm" variant="primary" icon={<Save className="tw:size-3.5" />} onClick={() => onSave(draft)}>Save</Button>
      )} />
      <div className="tw:px-4 tw:pb-4">
        <Textarea rows={4} value={draft} onChange={e => setDraft(e.target.value)} placeholder="What happened, scope, and current assessment" />
      </div>
    </div>
  );
}
