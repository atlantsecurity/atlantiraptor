// Admin setting: who must use two-factor sign in. Users who must but
// have not set it up are taken through setup at their next sign in.
import { useState } from 'react';
import { toast } from 'sonner';
import { Save, ShieldAlert } from 'lucide-react';
import { usePermission } from '../../lib/queries';
import { useGroups, useMfaPolicy, useSaveMfaPolicy, type MfaPolicy } from '../../lib/security';
import { Badge, Button, Card, CardHeader, Skeleton, cn } from '../../ui/primitives';
import { ROLE_INFO } from '../users/UsersPage';

const ROLES = ['administrator', 'org_admin', 'responder', 'hunter', 'investigator', 'artifact_writer', 'analyst', 'reader'];

export function MfaPolicyCard() {
  const isAdmin = usePermission('server_admin');
  const q = useMfaPolicy();
  if (!isAdmin) return null;
  if (q.isLoading) return <Card><div className="tw:p-4"><Skeleton className="tw:h-24" /></div></Card>;
  if (!q.data) return null;
  return <Editor key={JSON.stringify(q.data.policy)} initial={q.data.policy} breakGlass={!!q.data.break_glass_active} />;
}

function Editor({ initial, breakGlass }: { initial: MfaPolicy; breakGlass: boolean }) {
  const save = useSaveMfaPolicy();
  const { data: groups = [] } = useGroups();
  const [policy, setPolicy] = useState<MfaPolicy>({ roles: [], groups: [], ...initial });
  const dirty = JSON.stringify(policy) !== JSON.stringify({ roles: [], groups: [], ...initial });
  const toggle = (key: 'roles' | 'groups', value: string) => setPolicy(p => {
    const list = p[key] ?? [];
    return { ...p, [key]: list.includes(value) ? list.filter(v => v !== value) : [...list, value] };
  });

  const option = (mode: MfaPolicy['mode'], title: string, blurb: string) => (
    <button type="button" onClick={() => setPolicy(p => ({ ...p, mode }))}
      className={cn('tw:text-left tw:rounded-md tw:border tw:p-2.5',
        policy.mode === mode ? 'tw:border-accent tw:bg-accent-soft' : 'tw:border-line tw:hover:bg-hover')}>
      <div className="tw:text-[13px] tw:font-medium">{title}</div>
      <div className="tw:text-2xs tw:text-muted">{blurb}</div>
    </button>
  );

  return (
    <Card className="tw:xl:col-span-2">
      <CardHeader icon={<ShieldAlert className="tw:size-4" />} title="Two-factor policy (admin)"
        subtitle="Who must use two-factor sign in. Anyone who must but hasn't set it up is taken through setup at their next sign in."
        actions={breakGlass ? <Badge tone="bad">Disabled by ATLANTIRAPTOR_DISABLE_MFA</Badge> : undefined} />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-3 tw:gap-2">
          {option('all', 'Everyone', 'Recommended. Every user signing in with a password.')}
          {option('selected', 'Selected roles or groups', 'Only users with the roles or in the groups you pick.')}
          {option('off', 'Optional', 'Users can choose to turn it on themselves.')}
        </div>
        {policy.mode === 'selected' && (
          <div className="tw:space-y-2">
            <div className="tw:text-xs tw:font-medium">Roles</div>
            <div className="tw:flex tw:flex-wrap tw:gap-1.5">
              {ROLES.map(r => (
                <button key={r} type="button" onClick={() => toggle('roles', r)}
                  className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5 tw:text-xs',
                    policy.roles?.includes(r) ? 'tw:border-accent tw:bg-accent-soft tw:text-accent' : 'tw:border-line tw:hover:bg-hover')}>
                  {ROLE_INFO[r]?.label ?? r}
                </button>
              ))}
            </div>
            <div className="tw:text-xs tw:font-medium">Groups</div>
            <div className="tw:flex tw:flex-wrap tw:gap-1.5">
              {groups.length === 0 && <span className="tw:text-2xs tw:text-faint">No groups yet.</span>}
              {groups.map(g => (
                <button key={g.name} type="button" onClick={() => toggle('groups', g.name)}
                  className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5 tw:text-xs',
                    policy.groups?.includes(g.name) ? 'tw:border-accent tw:bg-accent-soft tw:text-accent' : 'tw:border-line tw:hover:bg-hover')}>
                  {g.name}
                </button>
              ))}
            </div>
          </div>
        )}
        <p className="tw:text-2xs tw:text-faint">
          Way back in if every admin loses their factor: start the server with ATLANTIRAPTOR_DISABLE_MFA=1. API clients that sign in with a password also need a second factor once it is required for them.
        </p>
        <div className="tw:flex tw:justify-end">
          <Button size="sm" variant="primary" icon={<Save className="tw:size-3.5" />} loading={save.isPending} disabled={!dirty}
            onClick={() => save.mutate(policy, {
              onSuccess: () => toast.success('Two-factor policy saved'),
              onError: e => toast.error((e as Error).message),
            })}>Save policy</Button>
        </div>
      </div>
    </Card>
  );
}
