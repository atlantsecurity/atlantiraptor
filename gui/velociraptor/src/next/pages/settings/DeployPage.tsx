// Server settings > Deploy a client: the same installer downloads that
// the Clients page offers, reachable from the settings section.
import { Rocket } from 'lucide-react';
import DeploySection from '../clients/DeploySection';

export default function DeployPage() {
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:pb-2">
        <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Rocket className="tw:size-5 tw:text-accent" />Deploy a client</h1>
        <p className="tw:text-xs tw:text-muted tw:mt-1">Installers and the Intune package for the endpoint agent. The same downloads are on the Clients page.</p>
      </div>
      <DeploySection noClients />
    </div>
  );
}
