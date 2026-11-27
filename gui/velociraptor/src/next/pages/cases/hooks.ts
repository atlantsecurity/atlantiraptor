import { useMemo } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import * as api from '../../lib/api';
import {
  useNewNotebook, useNotebook, useNotebookList, useTraits, type Notebook,
} from '../../lib/queries';
import {
  CASE_TAG_PREFIX, entry, isCaseDescription, newId, parseCase, serializeCase,
  type CaseLink, type CaseRecord, type CaseSeverity, type CaseSummary, type EntryKind,
} from './model';

export function useMe(): string {
  const { traits } = useTraits();
  return traits?.username ?? 'unknown';
}

export function useCases() {
  const list = useNotebookList();
  const cases: CaseSummary[] = useMemo(() => (list.data ?? [])
    .filter(r => isCaseDescription(r.Description))
    .map(r => {
      const rec = parseCase(r.Description, String(r.Name ?? ''));
      if (!rec) return null;
      return {
        ...rec,
        id: String(r.NotebookId),
        creator: String(r.Creator ?? ''),
        modified: new Date(String(r['Modified Time'] ?? '')).getTime() || 0,
      };
    })
    .filter((c): c is CaseSummary => !!c)
    .sort((a, b) => b.modified - a.modified), [list.data]);
  return { cases, isLoading: list.isLoading };
}

export function useCase(id: string | undefined) {
  const q = useNotebook(id);
  const record = useMemo(() => (q.data ? parseCase(q.data.description, q.data.name ?? '') : null), [q.data]);
  return { notebook: q.data, record, isLoading: q.isLoading, error: q.error };
}

async function fetchNotebook(id: string): Promise<Notebook> {
  const r = await api.get<{ items?: Notebook[] }>('v1/GetNotebooks', { notebook_id: id });
  const nb = r.items?.[0];
  if (!nb) throw new Error(`Case ${id} was not found.`);
  return nb;
}

// Every change re-reads the case right before writing, so concurrent
// edits by other analysts are merged rather than overwritten.
export function useCaseMutation() {
  const qc = useQueryClient();
  return async (id: string, change: (c: CaseRecord) => CaseRecord) => {
    const nb = await fetchNotebook(id);
    const current = parseCase(nb.description, nb.name ?? '');
    if (!current) throw new Error('This notebook is not a case.');
    const next = change(current);
    await api.post('v1/UpdateNotebook', { ...nb, name: `Case: ${next.title}`, description: serializeCase(next) });
    qc.invalidateQueries({ queryKey: ['notebook', id] });
    qc.invalidateQueries({ queryKey: ['notebook-list'] });
    return next;
  };
}

export function useCaseActions(id: string) {
  const mutate = useCaseMutation();
  const me = useMe();
  const log = (c: CaseRecord, kind: EntryKind, text: string): CaseRecord =>
    ({ ...c, timeline: [...c.timeline, entry(kind, me, text)] });

  return {
    addNote: (text: string) => mutate(id, c => log(c, 'note', text)),
    setStatus: (status: CaseRecord['status']) =>
      mutate(id, c => (c.status === status ? c : log({ ...c, status }, 'status', `Status set to ${status.replace('_', ' ')}`))),
    setSeverity: (severity: CaseSeverity) =>
      mutate(id, c => (c.severity === severity ? c : log({ ...c, severity }, 'severity', `Severity set to ${severity}`))),
    setOwner: (owner: string) =>
      mutate(id, c => (c.owner === owner ? c : log({ ...c, owner }, 'owner', owner ? `Assigned to ${owner}` : 'Unassigned'))),
    setSummary: (summary: string) =>
      mutate(id, c => (c.summary === summary ? c : log({ ...c, summary }, 'summary', 'Summary updated'))),
    unlink: (linkId: string) => mutate(id, c => {
      const l = c.links.find(x => x.id === linkId);
      if (!l) return c;
      return log({ ...c, links: c.links.filter(x => x.id !== linkId) }, 'unlink', `Removed ${l.kind} ${l.label}`);
    }),
  };
}

export type NewLink = Omit<CaseLink, 'id' | 'addedBy' | 'addedAt'>;

// Links an item to a case. Hunts are also tagged with the case so they
// can be found from the Hunts page.
export function useLinkToCase() {
  const mutate = useCaseMutation();
  const me = useMe();
  return async (caseId: string, link: NewLink) => {
    const rec = await mutate(caseId, c => {
      if (c.links.some(l => l.kind === link.kind && l.ref === link.ref)) return c;
      const full: CaseLink = { ...link, id: newId(), addedBy: me, addedAt: Date.now() };
      return {
        ...c,
        links: [...c.links, full],
        timeline: [...c.timeline, entry('link', me, `Linked ${link.kind} ${link.label}`)],
      };
    });
    if (link.kind === 'hunt') {
      const hunt = await api.get<{ tags?: string[] }>('v1/GetHunt', { hunt_id: link.ref });
      const tag = `${CASE_TAG_PREFIX}${caseId}`;
      const tags = hunt.tags ?? [];
      if (!tags.includes(tag)) await api.post('v1/ModifyHunt', { hunt_id: link.ref, tags: [...tags, tag] });
    }
    return rec;
  };
}

export function useCreateCase() {
  const create = useNewNotebook();
  const me = useMe();
  return async (p: { title: string; severity: CaseSeverity; summary: string; owner?: string }) => {
    const rec: CaseRecord = {
      title: p.title,
      status: 'open',
      severity: p.severity,
      owner: p.owner ?? me,
      summary: p.summary,
      links: [],
      timeline: [entry('created', me, 'Case opened')],
    };
    const nb = await create.mutateAsync({ name: `Case: ${p.title}`, description: serializeCase(rec), public: true });
    return nb.notebook_id;
  };
}
