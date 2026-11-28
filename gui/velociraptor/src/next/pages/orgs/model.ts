// Pure helpers for the Organizations page (unit tested with node --test).

export interface Org {
  id: string;
  name: string;
  root?: boolean;
  redirected?: boolean;
  users: number;
}

export const ORG_NAME_MAX = 100;

/** Returns a reason the name can not be used, or '' when it is fine. */
export function orgNameProblem(name: string, orgs: readonly Org[], selfId?: string): string {
  const n = name.trim();
  if (!n) return 'Enter a name.';
  if ([...n].length > ORG_NAME_MAX) return `At most ${ORG_NAME_MAX} characters.`;
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(n)) return 'No control characters.';
  if (orgs.some(o => o.id !== selfId && o.name.toLowerCase() === n.toLowerCase())) {
    return 'Another organization already has this name.';
  }
  return '';
}

