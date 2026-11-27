// Server event artifacts (alert forwarders) are switched on by adding
// them to the server monitoring table. The table is replaced as a whole
// on write, so every change re-reads it and keeps all other entries.
import { useMonitoringState, useSetMonitoringState, type MonitoringSpec, type MonitoringTable } from '../../lib/queries';

export function useServerMonitoring() {
  const state = useMonitoringState(true);
  const set = useSetMonitoringState(true);
  const table: MonitoringTable = state.data?.artifacts ?? {};

  const specOf = (artifact: string): Record<string, string> | null => {
    if (!(table.artifacts ?? []).includes(artifact)) return null;
    const spec = (table.specs ?? []).find(s => s.artifact === artifact);
    return Object.fromEntries((spec?.parameters?.env ?? []).map(e => [e.key, e.value]));
  };

  const write = async (change: (t: MonitoringTable) => MonitoringTable) => {
    const fresh = await state.refetch();
    if (!fresh.data) throw new Error('Could not read the server monitoring table.');
    await set.mutateAsync({ artifacts: change(fresh.data.artifacts ?? {}) });
  };

  const upsert = (artifact: string, params: Record<string, string>) => write(t => {
    const spec: MonitoringSpec = { artifact, parameters: { env: Object.entries(params).map(([key, value]) => ({ key, value })) } };
    return {
      ...t,
      artifacts: (t.artifacts ?? []).includes(artifact) ? t.artifacts : [...(t.artifacts ?? []), artifact],
      specs: [...(t.specs ?? []).filter(s => s.artifact !== artifact), spec],
    };
  });

  const remove = (artifact: string) => write(t => ({
    ...t,
    artifacts: (t.artifacts ?? []).filter(a => a !== artifact),
    specs: (t.specs ?? []).filter(s => s.artifact !== artifact),
  }));

  return { loaded: !!state.data, specOf, upsert, remove, busy: set.isPending };
}
