import { useMemo, useState } from 'react';
import {
  runArtifact, useEventTable, useMonitoringState, useSetMonitoringState,
  type ClientMonitoringState,
} from '../../../lib/queries';
import { ALERTS_ARTIFACT, DETECTION_MONITORS, SEVERITY_RANK, TEST_ALERT, toAlert, type Alert } from './model';

const WINDOW_SECONDS = 7 * 24 * 3600;
const MAX_ALERTS = 500;

// Alerts from the last 7 days, newest first. The window is fixed when the
// panel mounts so the query key stays stable while it polls.
export function useAlerts() {
  const [range] = useState(() => {
    const now = Math.floor(Date.now() / 1000);
    return { start: now - WINDOW_SECONDS, end: now + WINDOW_SECONDS };
  });
  const q = useEventTable('server', ALERTS_ARTIFACT, range, false, true);
  const alerts: Alert[] = useMemo(() => {
    const rows = (q.data?.pages ?? []).flatMap(p => p.rows);
    return rows.map(toAlert)
      .sort((a, b) => (b.time?.getTime() ?? 0) - (a.time?.getTime() ?? 0))
      .slice(0, MAX_ALERTS);
  }, [q.data]);
  return { alerts, isLoading: q.isLoading, error: q.error };
}

export function bySeverity(alerts: Alert[]): Alert[] {
  return [...alerts].sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || (b.time?.getTime() ?? 0) - (a.time?.getTime() ?? 0));
}

// Monitoring tables are replaced as a whole on write, so enabling the
// detection monitors reads the current table, adds what is missing and
// writes everything back.
function withMonitors(state: ClientMonitoringState, names: string[]): ClientMonitoringState {
  const table = state.artifacts ?? {};
  const current = table.artifacts ?? [];
  const missing = names.filter(n => !current.includes(n));
  return {
    ...state,
    artifacts: {
      ...table,
      artifacts: [...current, ...missing],
      specs: [...(table.specs ?? []), ...missing.map(artifact => ({ artifact, parameters: { env: [] } }))],
    },
  };
}

export function useDetectionSetup() {
  const state = useMonitoringState(false);
  const set = useSetMonitoringState(false);
  const enabled = state.data?.artifacts?.artifacts ?? [];
  const missing = DETECTION_MONITORS.filter(n => !enabled.includes(n));

  const enable = async () => {
    const fresh = await state.refetch();
    if (!fresh.data) throw new Error('Could not read the current client monitoring state.');
    await set.mutateAsync(withMonitors(fresh.data, DETECTION_MONITORS));
  };

  return {
    loaded: !!state.data,
    missing,
    enabling: set.isPending,
    enable,
  };
}

export async function sendTestAlert(clientId: string) {
  return runArtifact(clientId, TEST_ALERT, {}, true);
}
