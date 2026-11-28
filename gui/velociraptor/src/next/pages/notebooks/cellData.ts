// Report templates put chart rows in the cell's data field, a JSON map
// like {"table0": {"Response": "[...rows...]", "Columns": [...]}}, and
// point at them with value="data['table0']". Import-free for testing.

export interface InlineTable { rows: Record<string, unknown>[]; columns: string[] }

export function inlineTable(cellData: string | undefined, value: string | undefined): InlineTable | null {
  const key = /'([^']+)'/.exec(decodeURIComponent(value ?? ''))?.[1];
  if (!key || !cellData) return null;
  try {
    const entry = (JSON.parse(cellData) as Record<string, { Response?: string; Columns?: string[] }>)[key];
    if (!entry) return null;
    const rows = JSON.parse(entry.Response || '[]');
    if (!Array.isArray(rows)) return null;
    const columns = entry.Columns?.length ? entry.Columns : Object.keys(rows[0] ?? {});
    return { rows, columns };
  } catch {
    return null;
  }
}

/** A link from a template button: in-console (#/...) or http(s) only. */
export function buttonHref(href: string | undefined): string | null {
  const h = (href ?? '').trim();
  if (!h) return null;
  if (h.startsWith('#/')) return h;
  if (h.startsWith('/') && !h.startsWith('//')) return `#${h}`;
  try {
    const u = new URL(h);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}
