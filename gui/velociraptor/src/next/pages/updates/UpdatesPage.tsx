// Admin > Server updates: the server keeps itself on the latest signed
// Atlantiraptor release from GitHub. Checking, verifying and installing
// happen on the server; this page shows the state and the controls.
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { CloudDownload, ExternalLink, RefreshCw, ShieldCheck } from 'lucide-react';
import { useUpdateAction, useUpdateStatus, type UpdateStatus } from '../../lib/updates';
import { Badge, Button, Card, CardHeader, ConfirmDialog, EmptyState, Mono, Select, Skeleton, Switch } from '../../ui/primitives';

const HOURS = [1, 3, 6, 12, 24, 72, 168];
const STATE_LABEL: Record<UpdateStatus['state'], string> = {
  idle: '', checking: 'Checking GitHub…', downloading: 'Downloading…', verifying: 'Verifying the signature…', restarting: 'Restarting…',
};

const when = (secs?: number) => (secs ? new Date(secs * 1000).toLocaleString() : 'never');
const hoursLabel = (h: number) => (h < 24 ? `${h} hour${h === 1 ? '' : 's'}` : `${h / 24} day${h === 24 ? '' : 's'}`);

export default function UpdatesPage() {
  const { data, isLoading, error } = useUpdateStatus();
  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<CloudDownload />} title="Server updates are not available">{(error as Error)?.message}</EmptyState>;
  }
  return <Updates status={data} />;
}

function Updates({ status }: { status: UpdateStatus }) {
  const act = useUpdateAction();
  const [confirm, setConfirm] = useState(false);
  const [restarting, setRestarting] = useState(false);

  // After an install the server restarts; reload once it answers again.
  useEffect(() => {
    if (!restarting) return;
    const t = setInterval(() => {
      fetch(window.location.href, { cache: 'no-store' }).then(r => { if (r.ok) window.location.reload(); }).catch(() => undefined);
    }, 5000);
    return () => clearInterval(t);
  }, [restarting]);

  const busy = status.state !== 'idle' || act.isPending;
  const current = status.dev_build ? 'development build' : status.current_version;
  const canInstall = status.update_available && status.latest_has_binary && status.install_supported && status.running;

  const check = () => act.mutate({ action: 'check' }, {
    onSuccess: s => (s.last_error ? toast.error(s.last_error)
      : s.update_available ? toast.success(`Version ${s.latest_version} is available`) : toast.success('This server is up to date')),
    onError: e => toast.error((e as Error).message),
  });
  const install = () => act.mutate({ action: 'install' }, {
    onSuccess: () => { setConfirm(false); setRestarting(true); toast.success('Installed. The server is restarting; this page reloads when it is back.'); },
    onError: e => { setConfirm(false); toast.error((e as Error).message); },
  });
  const saveSettings = (auto_install: boolean, check_hours: number) => act.mutate({ action: 'settings', auto_install, check_hours }, {
    onSuccess: () => toast.success('Update settings saved'),
    onError: e => toast.error((e as Error).message),
  });

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-4xl">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><CloudDownload className="tw:size-5 tw:text-accent" />Server updates</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              This server installs new Atlantiraptor releases from GitHub ({status.repository}) by itself.
              A release is installed only if it is signed by Atlant Security and Windows trusts the signature.
            </p>
          </div>
          <Button icon={<RefreshCw className="tw:size-3.5" />} loading={status.state === 'checking'} disabled={busy} onClick={check}>Check now</Button>
        </div>

        {restarting && (
          <Card><div className="tw:px-4 tw:py-3 tw:text-[13px]">The new version is starting. This page reloads when the server answers again (usually under a minute).</div></Card>
        )}

        <Card>
          <CardHeader icon={<CloudDownload className="tw:size-4" />} title="Version"
            actions={STATE_LABEL[status.state] ? <Badge tone="warn" dot>{STATE_LABEL[status.state]}</Badge> : null} />
          <div className="tw:px-4 tw:py-3 tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3 tw:text-[13px]">
            <div>
              <div className="tw:text-2xs tw:text-muted">Running</div>
              <div className="tw:font-medium">{current} <span className="tw:text-muted tw:font-normal">({status.platform})</span></div>
            </div>
            <div>
              <div className="tw:text-2xs tw:text-muted">Latest release</div>
              <div className="tw:font-medium tw:flex tw:items-center tw:gap-2">
                {status.latest_version || 'unknown'}
                {status.latest_url && <a href={status.latest_url} target="_blank" rel="noreferrer" className="tw:text-accent"><ExternalLink className="tw:size-3.5" /></a>}
                {status.update_available ? <Badge tone="warn">update available</Badge>
                  : status.latest_version ? <Badge tone="ok">up to date</Badge> : null}
              </div>
            </div>
            <div className="tw:text-2xs tw:text-muted">Last checked {when(status.last_check)}{status.next_check ? ` · next check ${when(status.next_check)}` : ''}</div>
          </div>
          {(status.last_error || status.last_result) && (
            <div className="tw:px-4 tw:pb-3 tw:space-y-1 tw:text-xs">
              {status.last_result && <div className="tw:text-muted">{status.last_result}</div>}
              {status.last_error && <div className="tw:text-bad">{status.last_error}</div>}
            </div>
          )}
          <div className="tw:px-4 tw:pb-4 tw:flex tw:flex-wrap tw:items-center tw:gap-2">
            <Button variant="primary" icon={<CloudDownload className="tw:size-3.5" />} disabled={!canInstall || busy}
              loading={status.state === 'downloading' || status.state === 'verifying'} onClick={() => setConfirm(true)}>
              {status.update_available && status.latest_version ? `Install ${status.latest_version} now` : 'Install update'}
            </Button>
            {!status.install_supported && <span className="tw:text-2xs tw:text-muted">Installing is only supported on Windows servers; other platforms show updates only.</span>}
            {status.install_supported && status.update_available && !status.latest_has_binary &&
              <span className="tw:text-2xs tw:text-muted">The latest release has no signed Windows binary yet.</span>}
            {!status.running && <span className="tw:text-2xs tw:text-muted">The updater is not running in this server process.</span>}
          </div>
        </Card>

        <Card>
          <CardHeader icon={<RefreshCw className="tw:size-4" />} title="Automatic updates"
            actions={<Switch checked={status.settings.auto_install} disabled={busy}
              onChange={v => saveSettings(v, status.settings.check_hours)}
              label={status.settings.auto_install ? 'On' : 'Off'} />} />
          <div className="tw:px-4 tw:py-3 tw:space-y-2 tw:text-[13px]">
            <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
              <span>Check GitHub every</span>
              <Select value={status.settings.check_hours} disabled={busy}
                onChange={e => saveSettings(status.settings.auto_install, Number(e.target.value))}>
                {[...new Set([...HOURS, status.settings.check_hours])].sort((a, b) => a - b).map(h => <option key={h} value={h}>{hoursLabel(h)}</option>)}
              </Select>
            </div>
            <p className="tw:text-2xs tw:text-muted">
              When on, a newer release is installed as soon as it is found and the server restarts in the background,
              which interrupts the console for under a minute. When off, the server still checks and you install from this page.
            </p>
            {status.dev_build && <p className="tw:text-2xs tw:text-warn">This server runs a development build, so nothing is installed automatically. Install a release from this page to start receiving updates.</p>}
            {status.auto_disabled_by_env && <p className="tw:text-2xs tw:text-warn">ATLANTIRAPTOR_DISABLE_AUTO_UPDATE is set on the server: automatic installs are off.</p>}
            {status.settings.updated ? <p className="tw:text-2xs tw:text-faint">Last changed by {status.settings.updated_by} {when(status.settings.updated)}</p> : null}
          </div>
        </Card>

        <Card>
          <CardHeader icon={<ShieldCheck className="tw:size-4" />} title="What is checked before an install" />
          <ul className="tw:px-4 tw:pb-4 tw:pt-2 tw:text-xs tw:text-muted tw:space-y-1 tw:list-disc tw:list-inside">
            <li>The release comes from <Mono>{status.repository}</Mono> on GitHub, fixed in the binary; nothing at run time can point it elsewhere.</li>
            <li>The download matches the SHA-256 listed in the <Mono>SHA256SUMS</Mono> file of the release.</li>
            <li>It carries an Authenticode signature from <Mono>Atlant Security EOOD</Mono>, issued by Microsoft's code signing CA, that Windows trusts (with revocation checks).</li>
            <li>It runs and reports the version number of the release. Only then is it swapped in; the previous binary is kept until the next start.</li>
            <li>Every install and settings change is written to the audit log.</li>
          </ul>
        </Card>
      </div>

      <ConfirmDialog open={confirm} onOpenChange={setConfirm} title={`Install ${status.latest_version ?? 'the update'}?`}
        confirmLabel="Install and restart" loading={act.isPending} onConfirm={install}>
        The server downloads and verifies the release, then restarts in the background. The console and agent connections drop for under a minute.
      </ConfirmDialog>
    </div>
  );
}
