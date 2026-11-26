// Remote shell for one host: run a command, read its output on the page.
// Each command is one urgent collection of the shell artifact, so it is
// audited and access checked like any other collection.
import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ArrowLeft, Play, Terminal } from 'lucide-react';
import * as api from '../../lib/api';
import { runArtifacts, useClient, useFlowTable, usePermission } from '../../lib/queries';
import { parseTable } from '../../lib/table';
import type { TableResponse } from '../../lib/types';
import { timeAgo } from '../../lib/format';
import { osOf } from '../../lib/triage';
import { Badge, Button, Card, EmptyState, Kbd, Select, Skeleton, Textarea } from '../../ui/primitives';
import { FlowStateBadge } from '../collections/FlowDetail';

const SHELLS = [
  { id: 'powershell', label: 'PowerShell', artifact: 'Windows.System.PowerShell', os: ['windows'] },
  { id: 'cmd', label: 'cmd', artifact: 'Windows.System.CmdShell', os: ['windows'] },
  { id: 'bash', label: 'bash', artifact: 'Linux.Sys.BashShell', os: ['linux', 'darwin'] },
  { id: 'vql', label: 'VQL', artifact: 'Generic.Client.VQL', os: ['windows', 'linux', 'darwin', 'other'] },
];
const SHELL_RE = '(Windows.System.PowerShell|Windows.System.CmdShell|Linux.Sys.BashShell|Generic.Client.VQL)';

interface ShellRun { flowId: string; artifact: string; state: string; created: number; creator: string }

// The flow list leaves out collection parameters, so read the command
// from the request that was sent to the host. It never changes.
interface FlowRequests { items?: { FlowRequest?: { VQLClientActions?: { env?: { key: string; value: string }[] }[] } }[] }
function useRunCommand(clientId: string, flowId: string) {
  return useQuery({
    queryKey: ['shell-command', clientId, flowId],
    staleTime: Infinity,
    queryFn: async ({ signal }) => {
      const r = await api.get<FlowRequests>('v1/GetFlowRequests', { client_id: clientId, flow_id: flowId }, signal);
      for (const item of r.items ?? []) {
        for (const a of item.FlowRequest?.VQLClientActions ?? []) {
          const c = a.env?.find(e => e.key === 'Command');
          if (c) return c.value;
        }
      }
      return '';
    },
  });
}

const DONE_STATES = new Set(['FINISHED', 'ERROR']);

function useShellRuns(clientId: string) {
  return useQuery({
    queryKey: ['shell-runs', clientId],
    refetchInterval: 5_000,
    queryFn: async ({ signal }) => {
      const t = parseTable(await api.get<TableResponse>('v1/GetClientFlows', {
        client_id: clientId, rows: 30, start_row: 0, sort_direction: false,
        filter_column: 'Artifacts', filter_regex: SHELL_RE,
      }, signal));
      const runs: ShellRun[] = [];
      for (const r of t.rows) {
        const flow = r._Flow as { session_id?: string; state?: string; create_time?: number;
          request?: { artifacts?: string[]; creator?: string } } | undefined;
        const artifact = flow?.request?.artifacts?.[0] ?? '';
        if (!flow?.session_id || !SHELLS.some(s => s.artifact === artifact)) continue;
        runs.push({
          flowId: flow.session_id, artifact, state: String(flow.state ?? ''),
          created: Number(flow.create_time ?? 0), creator: flow.request?.creator ?? '',
        });
      }
      return runs;
    },
  });
}

export default function ShellPage() {
  const { client_id: clientId = '' } = useParams<{ client_id: string }>();
  const { data: client } = useClient(clientId);
  const os = osOf(client);
  const available = SHELLS.filter(s => s.os.includes(os));
  const [shellId, setShellId] = useState<string | null>(null);
  const shell = SHELLS.find(s => s.id === shellId) ?? available[0] ?? SHELLS[3];
  const [command, setCommand] = useState('');
  const [busy, setBusy] = useState(false);
  const canRun = usePermission('execve') || usePermission('collect_client');
  const runs = useShellRuns(clientId);
  const hostname = client?.os_info?.hostname || clientId;

  const run = async () => {
    if (!command.trim()) return;
    setBusy(true);
    try {
      await runArtifacts(clientId, [shell.artifact], { [shell.artifact]: shell.id === 'vql' ? { Command: command } : { Command: command, Stateful: 'N' } }, true);
      setCommand('');
      await runs.refetch();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-[1200px]">
        <div className="tw:flex tw:items-center tw:gap-3">
          <Link to={`/host/${clientId}`} className="tw:text-muted tw:hover:text-fg" aria-label="Back to host"><ArrowLeft className="tw:size-4" /></Link>
          <h1 className="tw:text-lg tw:font-semibold tw:flex tw:items-center tw:gap-2"><Terminal className="tw:size-5 tw:text-accent" />Shell on {hostname}</h1>
          {client && <Badge tone={client.last_seen_at && Date.now() - Number(client.last_seen_at) / 1000 < 60_000 ? 'ok' : 'neutral'} dot>
            seen {timeAgo(client.last_seen_at)}</Badge>}
        </div>
        <Card>
          <form className="tw:p-3 tw:space-y-2" onSubmit={e => { e.preventDefault(); void run(); }}>
            <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
              <Select value={shell.id} onChange={e => setShellId(e.target.value)} aria-label="Shell">
                {SHELLS.map(s => <option key={s.id} value={s.id}>{s.label}{s.os.includes(os) ? '' : ' (other OS)'}</option>)}
              </Select>
              <span className="tw:text-2xs tw:text-muted tw:font-mono">{shell.artifact}</span>
              <span className="tw:ml-auto tw:text-2xs tw:text-muted"><Kbd>Ctrl</Kbd>+<Kbd>Enter</Kbd> to run</span>
            </div>
            <Textarea value={command} onChange={e => setCommand(e.target.value)} rows={3}
              className="tw:font-mono tw:text-[12.5px]" placeholder={shell.id === 'vql' ? 'SELECT * FROM info()' : 'whoami /all'}
              onKeyDown={e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); void run(); } }} />
            <div className="tw:flex tw:items-center tw:gap-2">
              <Button type="submit" variant="primary" icon={<Play className="tw:size-3.5" />} loading={busy}
                disabled={!canRun || !command.trim()}>Run</Button>
              <span className="tw:text-2xs tw:text-muted">Runs on the host as the agent's account. Every command is recorded as a collection.</span>
            </div>
          </form>
        </Card>
        {runs.isLoading ? <Skeleton className="tw:h-24" />
          : (runs.data ?? []).length === 0 ? <EmptyState icon={<Terminal />} title="No commands yet">Commands and their output appear here, newest first.</EmptyState>
            : (runs.data ?? []).map(r => <RunCard key={r.flowId} clientId={clientId} run={r} />)}
      </div>
    </div>
  );
}

function RunCard({ clientId, run }: { clientId: string; run: ShellRun }) {
  const live = !DONE_STATES.has(run.state);
  const cmd = useRunCommand(clientId, run.flowId);
  const q = useFlowTable(clientId, run.flowId, { artifact: run.artifact }, live);
  const output = useMemo(() => (q.data?.pages ?? []).flatMap(p => p.rows), [q.data]);
  const text = run.artifact === 'Generic.Client.VQL'
    ? output.map(r => JSON.stringify(r)).join('\n')
    : output.map(r => `${String(r.Stdout ?? '')}${r.Stderr ? String(r.Stderr) : ''}`).filter(s => s.trim()).join('')
      + (output.some(r => r.StdoutUpload || r.StderrUpload) ? '\n[Output over 4 KB was saved as a file. Open the collection to read it.]' : '');
  return (
    <Card>
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:px-3 tw:py-2 tw:border-b tw:border-line tw:text-xs">
        <span className="tw:font-mono tw:font-medium tw:break-all tw:flex-1">{run.artifact === 'Generic.Client.VQL' ? '>' : '$'} {cmd.data ?? '…'}</span>
        <FlowStateBadge state={run.state} />
        <span className="tw:text-muted">{run.creator} · {timeAgo(run.created)}</span>
        <Link to={`/collected/${clientId}/${run.flowId}`} className="tw:text-accent tw:hover:underline">Collection</Link>
      </div>
      {/* Output from the endpoint: plain text only. */}
      <pre className="tw:m-0 tw:max-h-[420px] tw:overflow-auto tw:whitespace-pre-wrap tw:break-all tw:p-3 tw:font-mono tw:text-[12px] tw:bg-sunken">
        {q.isLoading ? 'Loading…' : text || (live ? 'Waiting for output…' : '(no output)')}
      </pre>
    </Card>
  );
}
