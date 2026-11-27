// Upgrades outdated agents of one OS. It shows exactly which package will
// be installed (the artifact's tool), refuses when no package is set, and
// warns when the package is upstream Velociraptor rather than this build.
import { useState } from 'react';
import { useHistory } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { AlertTriangle, ArrowUpCircle } from 'lucide-react';
import * as api from '../../lib/api';
import { useCreateHunt } from '../../lib/queries';
import type { ApiClient } from '../../lib/types';
import { Button, Dialog, Input, Mono, Skeleton, Textarea } from '../../ui/primitives';
import { useMe } from '../cases/hooks';
import { newId } from '../cases/model';
import { encodeUserData } from '../response/approval';
import { UPGRADE } from './model';

interface ToolInfo { name?: string; url?: string; filename?: string; hash?: string; version?: string; admin_override?: boolean; serve_locally?: boolean }

const CONFIRM = 'UPGRADE';

export function UpgradeDialog({ os, clients, onClose }: {
  os: keyof typeof UPGRADE; clients: ApiClient[]; onClose: () => void;
}) {
  const history = useHistory();
  const create = useCreateHunt();
  const me = useMe();
  const spec = UPGRADE[os];
  const tool = useQuery({
    queryKey: ['tool', spec.tool],
    queryFn: () => api.get<ToolInfo>('v1/GetToolInfo', { name: spec.tool }),
    retry: false,
  });
  const [typed, setTyped] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const t = tool.data;
  const hasPackage = !!(t?.filename || t?.url || t?.hash);
  const upstream = /velocidex/i.test(`${t?.url ?? ''} ${t?.filename ?? ''}`);
  const ready = hasPackage && typed.trim().toUpperCase() === CONFIRM && !!reason.trim() && clients.length > 0;

  const run = async () => {
    setBusy(true);
    const label = `upgrade-${newId()}`;
    try {
      await api.post('v1/LabelClients', { client_ids: clients.map(c => c.client_id), labels: [label], operation: 'set' });
      const r = await create.mutateAsync({
        hunt_description: `Agent upgrade (${spec.label}, ${clients.length} hosts)`,
        tags: ['fleet-upgrade'],
        start_request: {
          artifacts: [spec.artifact],
          specs: [{ artifact: spec.artifact, parameters: { env: [] } }],
          user_data: encodeUserData({ reason: reason.trim(), requested_by: me }),
        },
        condition: { labels: { label: [label] } },
        state: 2,
      });
      toast.success('Upgrade started');
      onClose();
      if (r.flow_id) history.push(`/hunts/${r.flow_id}`);
    } catch (e) {
      await api.post('v1/LabelClients', { client_ids: clients.map(c => c.client_id), labels: [label], operation: 'remove' }).catch(() => undefined);
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={v => !v && onClose()} width={620} title={`Upgrade ${clients.length} ${spec.label} agents`}
      description="Each host downloads and installs the package below, then restarts its agent."
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="danger" icon={<ArrowUpCircle className="tw:size-3.5" />} loading={busy} disabled={!ready} onClick={run}>Start upgrade</Button>
      </>}>
      <div className="tw:space-y-3 tw:text-xs">
        <div className="tw:rounded-md tw:border tw:border-line tw:p-3 tw:space-y-1">
          <div className="tw:font-medium">Package: tool <Mono>{spec.tool}</Mono> used by <Mono>{spec.artifact}</Mono></div>
          {tool.isLoading ? <Skeleton /> : hasPackage ? <>
            {t?.filename && <div>File: <Mono>{t.filename}</Mono></div>}
            {t?.url && <div className="tw:break-all">Source: <Mono>{t.url}</Mono></div>}
            {t?.hash && <div className="tw:break-all">SHA256: <Mono>{t.hash}</Mono></div>}
            {t?.version && <div>Version: {t.version}</div>}
          </> : (
            <div className="tw:text-bad">No package is set for this tool. Upload a repacked Atlantiraptor package for it under Artifacts › {spec.artifact} › Tools, then come back.</div>
          )}
        </div>
        {upstream && (
          <div className="tw:flex tw:gap-2 tw:rounded-md tw:border tw:border-warn/40 tw:bg-warn-soft tw:p-2.5 tw:text-warn">
            <AlertTriangle className="tw:size-4 tw:shrink-0" />
            This package comes from upstream Velociraptor (Velocidex), not your Atlantiraptor build. Installing it replaces your agents with upstream ones.
          </div>
        )}
        <label className="tw:block">
          <span className="tw:block tw:font-medium tw:mb-1">Reason (recorded in the audit log)</span>
          <Textarea rows={2} value={reason} onChange={e => setReason(e.target.value)} placeholder="e.g. roll out 0.77.5 to the fleet" />
        </label>
        <label className="tw:block">
          <span className="tw:block tw:font-medium tw:mb-1">Type {CONFIRM} to confirm</span>
          <Input value={typed} onChange={e => setTyped(e.target.value)} className="tw:font-mono" />
        </label>
      </div>
    </Dialog>
  );
}
