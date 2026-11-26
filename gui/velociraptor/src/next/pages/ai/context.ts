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
  let length = parts.join('\n').length;
  const push = (s: string) => { parts.push(s); length += s.length + 1; };
  for (const artifact of artifacts) {
    if (length > MAX_CONTEXT_CHARS) break;
    let resp: TableResponse | undefined;
    try {
      resp = await api.get<TableResponse>('v1/GetTable', {
        client_id: clientId, flow_id: flowId, artifact, start_row: 0, rows: ROWS_PER_ARTIFACT,
      });
    } catch (e) {
      push(`\n## ${artifact}: results could not be read (${(e as Error).message})`);
      continue;
    }
    const t = parseTable(resp);
    push(`\n## ${artifact} (${t.rows.length} of ${t.total || t.rows.length} rows shown)`);
    for (const r of t.rows) {
      if (length > MAX_CONTEXT_CHARS) break;
      push(JSON.stringify(r));
    }
  }
  return clip(parts.join('\n'));
}

export function jsonContext(label: string, value: unknown): string {
  return clip(`${label}\n${JSON.stringify(value, null, 1)}`);
}
