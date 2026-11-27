// Pure version comparison, kept import-free so it can be unit tested.
// Compares dotted versions numerically ("0.77.10" > "0.77.4").
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map(x => parseInt(x, 10));
  const pb = b.split(/[.\-+]/).map(x => parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number.isNaN(pa[i]) ? 0 : pa[i] ?? 0;
    const y = Number.isNaN(pb[i]) ? 0 : pb[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}
