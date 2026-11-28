// Where the console is served from, and links to server resources.
// The server may sit under a base path (for example /atlantiraptor/),
// and every internal link carries the current org.
import qs from 'qs';

// Paths the server serves itself (as opposed to console routes).
const SERVER_PATH = /^\/(api|app|notebooks|downloads|hunts|clients|auth)\//;

export function basePath(): string {
  if (import.meta.env.DEV) return '';
  let base = window.base_path || '';
  if (base === '') base = window.location.pathname.replace(/\/app.*$/, '');
  return base;
}

function joinPath(base: string, path: string): string {
  const b = base.replace(/\/+$/, '');
  const p = path.startsWith('/') ? path : `/${path}`;
  return `${b}${p}`;
}

/** A server path with the base path in front (data: URLs untouched). */
export function srcOf(url: string): string {
  if (/^data:/.test(url)) return url;
  const base = basePath();
  return url.startsWith(base) && base !== '' ? url : joinPath(base, url);
}

function currentOrg(): string {
  let org = window.globals?.OrgId || '';
  if (org.startsWith('{{')) org = '';
  return org || 'root';
}

/**
 * A full link to a server resource or console page, with the base path
 * and the org filled in. Only http(s) and relative URLs are allowed;
 * anything else becomes "#".
 */
export function href(url: string, params?: Record<string, unknown>): string {
  let parsed: URL;
  try {
    parsed = new URL(url, window.location.origin);
  } catch {
    return '#';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '#';

  const merged: Record<string, unknown> = { ...qs.parse(parsed.search.replace(/^\?/, '')), ...(params ?? {}) };
  if (!merged.org_id) merged.org_id = currentOrg();

  const base = basePath();
  let path = parsed.pathname;
  if (base && path.startsWith(base)) path = path.slice(base.length) || '/';
  parsed.pathname = SERVER_PATH.test(path.startsWith('/') ? path : `/${path}`) ? srcOf(path) : window.location.pathname;
  parsed.search = qs.stringify(merged, { indices: false });
  return parsed.href;
}
