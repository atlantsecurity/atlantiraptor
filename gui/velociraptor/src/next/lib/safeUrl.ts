// Links built from data (artifact references, tool URLs) are only made
// clickable for http and https, so a javascript: or data: URL in an
// artifact can never run in the console.
export function safeHttpUrl(value: string | undefined | null): string | null {
  if (!value) return null;
  try {
    const u = new URL(value.trim());
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}
