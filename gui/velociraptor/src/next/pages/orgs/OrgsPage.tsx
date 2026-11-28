// Organizations: separate tenants on one server, each with its own
// clients, hunts, artifacts and users. Org admins (administrators of the
// root org) create, rename and delete them here and choose who has access.
import { useMemo, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import {
  ArrowRightLeft, Building2, Check, ChevronDown, ChevronRight, Download, MoreHorizontal, Pencil, Plus, Trash2,
  TriangleAlert, UserPlus, Users as UsersIcon,
} from 'lucide-react';
import { currentOrgId } from '../../lib/api';
import { useAddUserOrgs, useGlobalUsers, useTraits } from '../../lib/queries';
import {
  orgClientConfigHref, orgNameProblem, orgSwitchHref, useCreateOrg, useDeleteOrg, useOrgs, useRenameOrg, type Org,
} from '../../lib/orgs';
import {
  Badge, Button, Card, Dialog, EmptyState, Field, Input, Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator,
  MenuTrigger, Mono, Skeleton, cn,
} from '../../ui/primitives';

// The org that `Atlantiraptor.exe gui` used to create for demos.
const isDemoOrg = (o: Org) => o.id === 'O123' && o.name === 'ACME Inc';

export default function OrgsPage() {
  const { data: orgs, isLoading, error } = useOrgs();
  const { updateTraits } = useTraits();
  const [creating, setCreating] = useState(false);
  const [renaming, setRenaming] = useState<Org | null>(null);
  const [deleting, setDeleting] = useState<Org | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const current = currentOrgId();

  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-60" /></div>;
  if (error) {
    return (
      <EmptyState className="tw:mt-24" icon={<Building2 />} title="Organizations are not available">
        {(error as Error).message}
      </EmptyState>
    );
  }
  const list = orgs ?? [];
  const demo = list.find(isDemoOrg);

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-5xl">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1 tw:min-w-[240px]">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2">
              <Building2 className="tw:size-5 tw:text-accent" />Organizations
            </h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Each organization is a separate tenant with its own clients, hunts, artifacts and users. Clients join an
              organization through its client config, so deploy agents with that org's config.
            </p>
          </div>
          <Button variant="primary" icon={<Plus />} onClick={() => setCreating(true)}>New organization</Button>
        </div>

        {demo && (
          <Card className="tw:p-4 tw:flex tw:items-start tw:gap-3 tw:border-warn/40">
            <TriangleAlert className="tw:size-4 tw:text-warn tw:mt-0.5 tw:shrink-0" />
            <div className="tw:flex-1 tw:text-[13px]">
              <div className="tw:font-medium">“ACME Inc” is the demo organization from the quick start</div>
              <div className="tw:text-muted tw:text-xs tw:mt-0.5">
                Earlier versions of <Mono>Atlantiraptor.exe gui</Mono> created it automatically. If you never enrolled
                clients or ran hunts in it, you can delete it. Check its clients first: deleting removes all of its data.
              </div>
            </div>
            <Button size="sm" variant="secondary" icon={<ArrowRightLeft />}
              onClick={() => window.location.assign(orgSwitchHref(demo.id))}>Open it</Button>
            <Button size="sm" variant="danger" icon={<Trash2 />} onClick={() => setDeleting(demo)}>Delete…</Button>
          </Card>
        )}

        <Card className="tw:divide-y tw:divide-line">
          {list.map(o => (
            <OrgRow key={o.id} org={o} current={o.id === current} expanded={open === o.id}
              onToggle={() => setOpen(open === o.id ? null : o.id)}
              onRename={() => setRenaming(o)} onDelete={() => setDeleting(o)} />
          ))}
          {list.length === 0 && <div className="tw:p-6 tw:text-sm tw:text-muted">No organizations.</div>}
        </Card>

        <p className="tw:text-2xs tw:text-faint">
          Only administrators of the root organization can see this page. Every change is recorded in the audit log.
        </p>
      </div>

      <CreateOrgDialog open={creating} onOpenChange={setCreating} orgs={list}
        onCreated={o => { updateTraits(); setOpen(o.id); }} />
      {renaming && <RenameOrgDialog org={renaming} orgs={list} onClose={() => setRenaming(null)}
        onDone={() => updateTraits()} />}
      {deleting && <DeleteOrgDialog org={deleting} current={deleting.id === current} onClose={() => setDeleting(null)}
        onDone={() => updateTraits()} />}
    </div>
  );
}

function OrgRow({ org, current, expanded, onToggle, onRename, onDelete }: {
  org: Org; current: boolean; expanded: boolean; onToggle: () => void; onRename: () => void; onDelete: () => void;
}) {
  return (
    <div>
      <div className="tw:flex tw:items-center tw:gap-3 tw:px-4 tw:py-3">
        <button type="button" onClick={onToggle} aria-expanded={expanded}
          className="tw:flex tw:items-center tw:gap-3 tw:flex-1 tw:min-w-0 tw:text-left">
          {expanded ? <ChevronDown className="tw:size-4 tw:text-faint tw:shrink-0" /> : <ChevronRight className="tw:size-4 tw:text-faint tw:shrink-0" />}
          <span className="tw:flex tw:items-center tw:justify-center tw:size-8 tw:rounded-md tw:bg-accent-soft tw:text-accent tw:shrink-0">
            <Building2 className="tw:size-4" />
          </span>
          <span className="tw:min-w-0 tw:flex-1">
            <span className="tw:flex tw:items-center tw:gap-2 tw:flex-wrap">
              <span className="tw:text-[13px] tw:font-semibold tw:truncate">{org.root ? 'Root organization' : org.name}</span>
              {current && <Badge tone="accent" dot>current</Badge>}
              {org.redirected && <Badge tone="warn">redirected</Badge>}
            </span>
            <span className="tw:flex tw:items-center tw:gap-3 tw:text-2xs tw:text-faint tw:mt-0.5">
              <Mono>{org.id}</Mono>
              <span className="tw:flex tw:items-center tw:gap-1"><UsersIcon className="tw:size-3" />
                {org.users} {org.users === 1 ? 'user' : 'users'}</span>
            </span>
          </span>
        </button>
        {!current && (
          <Button size="sm" variant="ghost" icon={<ArrowRightLeft />} className="tw:max-sm:hidden"
            onClick={() => window.location.assign(orgSwitchHref(org.id))}>Switch</Button>
        )}
        <Menu>
          <MenuTrigger asChild>
            <Button size="sm" variant="ghost" icon={<MoreHorizontal />} aria-label={`Actions for ${org.name}`} />
          </MenuTrigger>
          <MenuContent>
            <MenuLabel>{org.root ? 'Root organization' : org.name}</MenuLabel>
            {!current && <MenuItem icon={<ArrowRightLeft />} onSelect={() => window.location.assign(orgSwitchHref(org.id))}>Switch to this organization</MenuItem>}
            <MenuItem icon={<Download />} onSelect={() => window.location.assign(orgClientConfigHref(org.id))}>Download client config</MenuItem>
            {!org.root && !org.redirected && <>
              <MenuItem icon={<Pencil />} onSelect={onRename}>Rename…</MenuItem>
              <MenuSeparator />
              <MenuItem danger icon={<Trash2 />} onSelect={onDelete}>Delete…</MenuItem>
            </>}
          </MenuContent>
        </Menu>
      </div>
      {expanded && <OrgMembers org={org} />}
    </div>
  );
}

function OrgMembers({ org }: { org: Org }) {
  const history = useHistory();
  const { data: users, isLoading } = useGlobalUsers();
  const addOrgs = useAddUserOrgs();
  const members = useMemo(() => (users ?? []).filter(u => (u.orgs ?? []).some(o => o.id === org.id)), [users, org.id]);
  const others = useMemo(() => (users ?? []).filter(u => !members.includes(u)), [users, members]);
  const label = org.root ? 'the root organization' : org.name;

  const add = (name: string) => addOrgs.mutate({ name, orgs: [org.id], roles: ['reader'] }, {
    onSuccess: () => toast.success(`${name} can now read ${label}. Adjust their roles on the Users page.`),
    onError: e => toast.error(`Could not add ${name}: ${(e as Error).message}`),
  });

  return (
    <div className="tw:px-4 tw:pb-4 tw:pl-[60px]">
      <div className="tw:flex tw:items-center tw:gap-2 tw:mb-2">
        <span className="tw:text-xs tw:font-semibold tw:text-muted tw:flex-1">Members</span>
        {others.length > 0 && (
          <Menu>
            <MenuTrigger asChild>
              <Button size="sm" variant="secondary" icon={<UserPlus />} loading={addOrgs.isPending}>Add user</Button>
            </MenuTrigger>
            <MenuContent>
              <MenuLabel>Grant read-only access to {label}</MenuLabel>
              {others.map(u => <MenuItem key={u.name} onSelect={() => add(u.name)}>{u.name}</MenuItem>)}
            </MenuContent>
          </Menu>
        )}
        <Button size="sm" variant="ghost" icon={<Plus />} onClick={() => history.push('/users?add=1')}>New user</Button>
      </div>
      {isLoading && <Skeleton className="tw:h-16" />}
      {!isLoading && members.length === 0 && (
        <div className="tw:text-xs tw:text-faint tw:py-2">Nobody has access yet. Add a user to give them access.</div>
      )}
      <div className="tw:flex tw:flex-wrap tw:gap-1.5">
        {members.map(u => (
          <button key={u.name} type="button" onClick={() => history.push(`/users/${encodeURIComponent(u.name)}`)}
            title="Change their roles"
            className="tw:h-7 tw:px-2.5 tw:rounded-full tw:border tw:border-line tw:text-xs tw:hover:bg-hover tw:flex tw:items-center tw:gap-1">
            {u.name}
          </button>
        ))}
      </div>
      <p className="tw:text-2xs tw:text-faint tw:mt-2">
        Click a person to change their roles in this organization, or to remove them from it.
      </p>
    </div>
  );
}

function CreateOrgDialog({ open, onOpenChange, orgs, onCreated }: {
  open: boolean; onOpenChange: (v: boolean) => void; orgs: Org[]; onCreated: (o: Org) => void;
}) {
  const [name, setName] = useState('');
  const create = useCreateOrg();
  const problem = name ? orgNameProblem(name, orgs) : '';
  const close = () => { onOpenChange(false); setName(''); };
  const submit = () => {
    if (!name.trim() || problem) return;
    create.mutate({ name }, {
      onSuccess: d => {
        toast.success(`Created ${d.org?.name ?? name}. You are its administrator.`);
        close();
        if (d.org) onCreated(d.org);
      },
      onError: e => toast.error((e as Error).message),
    });
  };
  return (
    <Dialog open={open} onOpenChange={o => (o ? onOpenChange(true) : close())} title="New organization" width={460}
      description="A new, empty tenant. You become its administrator; add other people afterwards."
      footer={<>
        <Button variant="ghost" onClick={close}>Cancel</Button>
        <Button variant="primary" icon={<Plus />} disabled={!name.trim() || !!problem} loading={create.isPending}
          onClick={submit}>Create</Button>
      </>}>
      <Field label="Name" required hint={problem || 'For example the customer or business unit it holds.'}>
        <Input value={name} onChange={e => setName(e.target.value)} autoFocus placeholder="Customer name"
          maxLength={100} onKeyDown={e => e.key === 'Enter' && submit()} />
      </Field>
    </Dialog>
  );
}

function RenameOrgDialog({ org, orgs, onClose, onDone }: {
  org: Org; orgs: Org[]; onClose: () => void; onDone: () => void;
}) {
  const [name, setName] = useState(org.name);
  const rename = useRenameOrg();
  const problem = orgNameProblem(name, orgs, org.id);
  const unchanged = name.trim() === org.name;
  const submit = () => {
    if (problem || unchanged) return;
    rename.mutate({ id: org.id, name }, {
      onSuccess: () => { toast.success(`Renamed to ${name.trim()}`); onDone(); onClose(); },
      onError: e => toast.error((e as Error).message),
    });
  };
  return (
    <Dialog open onOpenChange={o => !o && onClose()} title={`Rename ${org.name}`} width={460}
      description="Only the display name changes. The org ID and enrolled clients stay as they are."
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" icon={<Check />} disabled={!!problem || unchanged} loading={rename.isPending}
          onClick={submit}>Rename</Button>
      </>}>
      <Field label="Name" required hint={problem || undefined}>
        <Input value={name} onChange={e => setName(e.target.value)} autoFocus maxLength={100}
          onKeyDown={e => e.key === 'Enter' && submit()} />
      </Field>
    </Dialog>
  );
}

function DeleteOrgDialog({ org, current, onClose, onDone }: {
  org: Org; current: boolean; onClose: () => void; onDone: () => void;
}) {
  const [typed, setTyped] = useState('');
  const del = useDeleteOrg();
  const ok = typed.trim() === org.name;
  const submit = () => {
    if (!ok) return;
    del.mutate({ id: org.id, confirm: typed.trim() }, {
      onSuccess: () => {
        toast.success(`Deleted ${org.name}`);
        // The console was showing the org that no longer exists.
        if (current) { window.location.assign(orgSwitchHref('root')); return; }
        onDone();
        onClose();
      },
      onError: e => toast.error((e as Error).message),
    });
  };
  return (
    <Dialog open onOpenChange={o => !o && onClose()} title={`Delete ${org.name}?`} width={480}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="danger" icon={<Trash2 />} disabled={!ok} loading={del.isPending} onClick={submit}>
          Delete organization
        </Button>
      </>}>
      <div className="tw:flex tw:flex-col tw:gap-3 tw:text-[13px]">
        <p className="tw:text-muted">
          This permanently removes everything stored for <b className="tw:text-fg">{org.name}</b>: its clients, collected
          results, hunts, notebooks, artifacts and settings. Users lose access to it ({org.users}{' '}
          {org.users === 1 ? 'user' : 'users'}); their accounts stay. Agents enrolled in it stop reporting.
          There is no undo.
        </p>
        <Field label={<>Type <b>{org.name}</b> to confirm</>}>
          <Input value={typed} onChange={e => setTyped(e.target.value)} autoFocus
            className={cn(typed && !ok && 'tw:border-bad')} onKeyDown={e => e.key === 'Enter' && submit()} />
        </Field>
      </div>
    </Dialog>
  );
}
