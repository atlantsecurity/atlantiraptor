// "Respond to all": the hosts of a hunt that returned at least one row,
// read from the server's per-host hunt flows, so the list covers every
// matching host and not only the rows loaded in the browser.
import * as api from '../../lib/api';
import { parseTable } from '../../lib/table';
import type { TableResponse } from '../../lib/types';
import { matchedHosts } from './huntTargetsModel';
import type { PickedClient } from './ClientPicker';

const PAGE = 2000;

export async function huntMatchedHosts(huntId: string, max: number): Promise<{ hosts: PickedClient[]; truncated: boolean }> {
  const hosts: PickedClient[] = [];
  for (let start = 0; ; start += PAGE) {
    const page = parseTable(await api.get<TableResponse>('v1/GetHuntFlows', {
      hunt_id: huntId, start_row: start, rows: PAGE,
    }));
    hosts.push(...matchedHosts(page.rows));
    if (hosts.length > max) return { hosts: hosts.slice(0, max), truncated: true };
    if (page.rows.length < PAGE) return { hosts, truncated: false };
  }
}
