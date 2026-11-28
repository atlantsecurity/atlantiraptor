// Per-tab state kept in session storage (selected client, last
// collection opened, ...), so a reload returns to the same place.
export const schema = {
  CurrentSelectedClientKey: 'CurrentSelectedClient',
  CurrentSelectedArtifactKey: 'CurrentSelectedArtifact',
  CurrentServerEventArtifactKey: 'CurrentServerEventArtifact',
  ServerCurrentFlowKey: 'ServerCurrentFlow',
  ClientsCurrentFlowKey: 'ClientsCurrentFlow',
  CurrentNotebookIdKey: 'CurrentNotebookId',
  CurrentVFSPathKey: 'CurrentVFSPath',
} as const;

export function setItem(key: string, value: string): void {
  try { sessionStorage.setItem(key, value); } catch { /* storage full or disabled */ }
}

export function getItem(key: string): string | null {
  try { return sessionStorage.getItem(key); } catch { return null; }
}
