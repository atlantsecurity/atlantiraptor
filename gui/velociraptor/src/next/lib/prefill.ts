// Hand-offs between screens: text to prefill on the next screen.

export const IOC_PREFILL_KEY = 'atl-ioc-prefill';

/** Opens IOC sweep with these indicators already pasted. */
export function prefillIocSweep(text: string) {
  try {
    sessionStorage.setItem(IOC_PREFILL_KEY, text);
  } catch {
    // ignore: the page simply opens empty
  }
}

/** Dashboard URL with the Rapid hunt box prefilled (not started). */
export function rapidHuntUrl(indicator: string): string {
  return `/dashboard?rapid=${encodeURIComponent(indicator)}`;
}
