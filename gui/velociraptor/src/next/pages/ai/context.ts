// Builds the text sent for AI triage. Everything is capped so a large
// collection cannot send megabytes of endpoint data to a third party.
import * as api from '../../lib/api';
import { parseTable } from '../../lib/table';
import type { TableResponse } from '../../lib/types';

export const MAX_CONTEXT_CHARS = 60_000;
const ROWS_PER_ARTIFACT = 200;

export function clip(s: string, max = MAX_CONTEXT_CHARS): string {
  return s.length > max ? `${s.slice(0, max)}\n…[truncated at ${max} characters]` : s;
}

export async function flowContext(clientId: string, flowId: string, artifacts: string[], hostname: string): Promise<string> {
  const parts: string[] = [`Host: ${hostname} (${clientId})`, `Collection: ${flowId}`];
  for (const artifact of artifacts) {
    const resp = await api.get<TableResponse>('v1/GetTable', {
      client_id: clientId, flow_id: flowId, artifact, start_row: 0, rows: ROWS_PER_ARTIFACT,
    }).catch(() => undefined);
    const t = parseTable(resp);
    parts.push(`\n## ${artifact} (${t.rows.length} of ${t.total || t.rows.length} rows shown)`);
    parts.push(...t.rows.map(r => JSON.stringify(r)));
    if (parts.join('\n').length > MAX_CONTEXT_CHARS) break;
  }
  return clip(parts.join('\n'));
}

export function jsonContext(label: string, value: unknown): string {
  return clip(`${label}\n${JSON.stringify(value, null, 1)}`);
}
