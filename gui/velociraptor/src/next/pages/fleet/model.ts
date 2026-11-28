// The artifacts and tools used to upgrade agents, per OS. The OS keys
// match the "os" field of the fleet summary (lower case).
export const UPGRADE = {
  windows: { artifact: 'Admin.Client.Upgrade.Windows', tool: 'WindowsMSI', label: 'Windows' },
  linux: { artifact: 'Admin.Client.Upgrade.Debian', tool: 'VelociraptorDebian', label: 'Linux (Debian)' },
} as const;

export type UpgradeOs = keyof typeof UPGRADE;

export { compareVersions } from './versions';
export { fleetVersions, type FleetHost, type FleetSummary } from './summary';
