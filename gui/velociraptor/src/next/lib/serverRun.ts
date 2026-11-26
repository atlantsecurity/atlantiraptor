// Runs a SERVER artifact, waits for it to finish and returns its rows.
// Used by features that call out to other systems from the server (MISP
// import, AI triage), so credentials stay in server-side secrets.
import * as api from './api';
import { parseTable, type Row } from './table';
import type { FlowDetails, TableResponse } from './types';

const POLL_MS = 1_000;

export interface ServerRunResult { flowId: string; rows: Row[]; logs: string[] }

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export async function runServerArtifact(
  artifact: string, params: Record<string, string>, opts: { timeoutMs?: number; userData?: string } = {},
): Promise<ServerRunResult> {
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const r = await api.post<{ flow_id?: string }>('v1/CollectArtifact', {
    client_id: 'server',
    artifacts: [artifact],
    specs: [{ artifact, parameters: { env: Object.entries(params).map(([key, value]) => ({ key, value })) } }],
    user_data: opts.userData || undefined,
  });
  const flowId = r.flow_id;
  if (!flowId) throw new Error(`The server did not start ${artifact}.`);

  const deadline = Date.now() + timeoutMs;
  let state = '';
  while (Date.now() < deadline) {
    const d = await api.get<FlowDetails>('v1/GetFlowDetails', { client_id: 'server', flow_id: flowId });
    state = String(d.context?.state ?? '');
    if (state === 'FINISHED' || state === 'ERROR') break;
    await sleep(POLL_MS);
  }

  const logsResp = await api.get<TableResponse>('v1/GetTable',
    { client_id: 'server', flow_id: flowId, type: 'log', start_row: 0, rows: 50 }).catch(() => undefined);
  const logs = parseTable(logsResp).rows.map(l => String(l.message ?? l.Message ?? '')).filter(Boolean);

  if (state === 'ERROR') {
    const err = logs.filter(l => /error/i.test(l)).slice(-3).join(' | ');
    throw new Error(`${artifact} failed${err ? `: ${err}` : ''}. See server collection ${flowId}.`);
  }
  if (state !== 'FINISHED') throw new Error(`${artifact} is still running after ${Math.round(timeoutMs / 1000)}s. See server collection ${flowId}.`);

  const resp = await api.get<TableResponse>('v1/GetTable',
    { client_id: 'server', flow_id: flowId, artifact, start_row: 0, rows: 10_000 }).catch(() => undefined);
  return { flowId, rows: parseTable(resp).rows, logs };
}
