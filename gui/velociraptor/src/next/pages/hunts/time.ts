// Helpers for <input type="datetime-local">, which works in local time.
export function toLocalInput(d: Date | null): string {
  if (!d) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fromLocalInput(v: string): Date | null {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Hunts stop after an hour unless started with "Run until stopped",
// which sets an expiry ten years out.
export const DEFAULT_HUNT_HOURS = 1;
const UNTIL_STOPPED_MS = 10 * 365 * 24 * 3600 * 1000;

/** Expiry, in microseconds as the API wants it, for "Run until stopped". */
export function untilStoppedExpiry(now = Date.now()): number {
  return (now + UNTIL_STOPPED_MS) * 1000;
}

/** True when a hunt's expiry (any epoch unit) is so far off it means "until stopped". */
export function runsUntilStopped(expiresMs: number | null | undefined, now = Date.now()): boolean {
  return !!expiresMs && expiresMs - now > 5 * 365 * 24 * 3600 * 1000;
}

export function hoursLabel(h: number): string {
  if (h % 24 === 0) return `${h / 24} day${h === 24 ? '' : 's'}`;
  return `${h} hour${h === 1 ? '' : 's'}`;
}
