// Groups give roles to many users at once, in the current org. The
// server merges group roles into each member's permissions and enforces
// them on every request.
import { useState } from 'react';
import { toast } from 'sonner';
import { Plus, Save, Trash2, UsersRound } from 'lucide-react';
import { useGlobalUsers } from '../../lib/queries';
import { useGroups, useSaveGroups, type Group } from '../../lib/security';
import { Badge, Button, Card, CardHeader, EmptyState, IconButton, Input, Skeleton, cn } from '../../ui/primitives';
import { TagInput } from '../hunts/TagInput';
import { ROLE_INFO } from './UsersPage';

const ASSIGNABLE = ['reader', 'analyst', 'investigator', 'hunter', 'responder', 'artifact_writer', 'administrator', 'org_admin'];

export default function GroupsPage() {
  const { data, isLoading, error } = useGroups();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error) {
    return <EmptyState icon={<UsersRound />} title="Groups are not available">{(error as Error).message}</EmptyState>;
  }
  return <Editor key={JSON.stringify(data)} initial={data ?? []} />;
}

function Editor({ initial }: { initial: Group[] }) {
  const save = useSaveGroups();
  const { data: users = [] } = useGlobalUsers();
  const [groups, setGroups] = useState<Group[]>(initial);
  const dirty = JSON.stringify(groups) !== JSON.stringify(initial);
  const update = (i: number, patch: Partial<Group>) =>
    setGroups(gs => gs.map((g, j) => (j === i ? { ...g, ...patch } : g)));

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><UsersRound className="tw:size-5 tw:text-accent" />Groups</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Give roles to many people at once. Members get the group's roles on top of their own, in this org, enforced by the server.
            </p>
          </div>
          <Button variant="secondary" icon={<Plus className="tw:size-3.5" />}
            onClick={() => setGroups(gs => [...gs, { name: `Group ${gs.length + 1}`, roles: ['hunter'], members: [] }])}>New group</Button>
          <Button variant="primary" icon={<Save className="tw:size-3.5" />} loading={save.isPending} disabled={!dirty}
            onClick={() => save.mutate(groups, {
              onSuccess: () => toast.success('Groups saved'),
              onError: e => toast.error((e as Error).message),
            })}>Save changes</Button>
        </div>

        {groups.length === 0 && (
          <Card><EmptyState icon={<UsersRound />} title="No groups yet">For example: “SOC Tier 1” with the Hunter role, “Incident response” with Responder.</EmptyState></Card>
        )}

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          {groups.map((g, i) => (
            <Card key={i}>
              <CardHeader icon={<UsersRound className="tw:size-4" />}
                title={<Input value={g.name} onChange={e => update(i, { name: e.target.value })} className="tw:h-7 tw:text-[13px] tw:font-medium" />}
                actions={<IconButton size="xs" variant="ghost" label="Delete group" icon={<Trash2 className="tw:size-3.5" />}
                  onClick={() => setGroups(gs => gs.filter((_, j) => j !== i))} />} />
              <div className="tw:px-4 tw:pb-4 tw:space-y-3">
                <Input value={g.description ?? ''} onChange={e => update(i, { description: e.target.value })} placeholder="What this group is for (optional)" className="tw:text-xs" />
                <div>
                  <div className="tw:text-xs tw:font-medium tw:mb-1.5">Roles</div>
                  <div className="tw:flex tw:flex-wrap tw:gap-1.5">
                    {ASSIGNABLE.map(r => {
                      const on = g.roles.includes(r);
                      return (
                        <button key={r} type="button" title={ROLE_INFO[r]?.blurb}
                          onClick={() => update(i, { roles: on ? g.roles.filter(x => x !== r) : [...g.roles, r] })}
                          className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5 tw:text-xs',
                            on ? 'tw:border-accent tw:bg-accent-soft tw:text-accent tw:font-medium' : 'tw:border-line tw:hover:bg-hover')}>
                          {ROLE_INFO[r]?.label ?? r}{ROLE_INFO[r]?.danger && on ? ' ⚠' : ''}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div>
                  <div className="tw:text-xs tw:font-medium tw:mb-1.5">Members <Badge tone="neutral">{g.members.length}</Badge></div>
                  <TagInput value={g.members} onChange={m => update(i, { members: m })}
                    suggestions={users.map(u => u.name)} placeholder="Add a user name" tone="accent" />
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
