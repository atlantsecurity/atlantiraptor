// Clients > Deploy a client: shows server administrators how to install
// the agent on more computers, with the org's client configuration
// (server address, CA certificate and enrollment nonce) built into
// ready-to-copy commands, scripts and an Intune package.
import { useState } from 'react';
import { toast } from 'sonner';
import { ChevronDown, Download, ExternalLink, KeyRound, Rocket, TriangleAlert } from 'lucide-react';
import { downloadDeployFile, useDeployInfo, type DeployInfo } from '../../lib/deploy';
import { Badge, Button, CopyButton, Mono, Skeleton, Tabs, cn } from '../../ui/primitives';

const DOCS = 'https://atlantsecurity.github.io/atlantiraptor';
const OPEN_KEY = 'atl.clients.deploy.open';

type OsTab = 'windows' | 'linux' | 'macos' | 'intune';

// The visitor's choice, or null to open it only while there are no clients.
function readOpen(): boolean | null {
  try {
    const v = window.localStorage.getItem(OPEN_KEY);
    return v === null ? null : v === '1';
  } catch {
    return null;
  }
}

export default function DeploySection({ noClients }: { noClients: boolean }) {
  const [choice, setChoice] = useState<boolean | null>(readOpen);
  const open = choice ?? noClients;
  const { data, isLoading, error } = useDeployInfo(open);
  const toggle = () => {
    const next = !open;
    setChoice(next);
    try { window.localStorage.setItem(OPEN_KEY, next ? '1' : '0'); } catch { /* private window */ }
  };

  return (
    <section className="tw:border-t tw:border-line tw:bg-canvas tw:shrink-0" aria-label="Deploy a client">
      <button type="button" onClick={toggle} aria-expanded={open}
        className="tw:w-full tw:flex tw:items-center tw:gap-2 tw:px-5 tw:h-10 tw:text-left tw:hover:bg-hover">
        <Rocket className="tw:size-4 tw:text-accent" />
        <span className="tw:text-[13px] tw:font-semibold">Deploy a client</span>
        <span className="tw:text-xs tw:text-muted tw:truncate">
          Install the agent on Windows, Linux or macOS computers, or with Intune, so they connect to this server
        </span>
        <ChevronDown className={cn('tw:size-4 tw:ml-auto tw:text-faint tw:transition-transform', open && 'tw:rotate-180')} />
      </button>
      {open && (
        <div className="tw:max-h-[60vh] tw:overflow-y-auto tw:border-t tw:border-line">
          {isLoading ? <div className="tw:p-5"><Skeleton className="tw:h-32" /></div>
            : error || !data ? (
              <div className="tw:px-5 tw:py-4 tw:text-[13px] tw:text-muted">{(error as Error)?.message || 'Not available.'}</div>
            ) : <Deploy info={data} />}
        </div>
      )}
    </section>
  );
}

function download(name: string) {
  downloadDeployFile(name).catch(e => toast.error((e as Error).message));
}

function Deploy({ info }: { info: DeployInfo }) {
  const [tab, setTab] = useState<OsTab>('windows');
  const [showConfig, setShowConfig] = useState(false);

  return (
    <div className="tw:px-5 tw:py-4 tw:space-y-4 tw:max-w-5xl tw:text-[13px]">
      {info.local_only && (
        <div className="tw:flex tw:gap-2 tw:rounded-md tw:bg-warn-soft tw:px-3 tw:py-2 tw:text-warn">
          <TriangleAlert className="tw:size-4 tw:shrink-0 tw:mt-0.5" />
          <div>
            Agents are told to connect to <Mono>{info.server_urls.join(', ')}</Mono>, which only works on this computer
            (the one-computer test lab). To add other computers, set up the server with an address they can
            reach: see <a className="tw:underline" href={`${DOCS}/quickstart/#b-a-server-and-a-second-computer`} target="_blank" rel="noreferrer">Set up a test lab, part B</a>.
          </div>
        </div>
      )}

      <div className="tw:space-y-1.5">
        <h4 className="tw:font-semibold tw:flex tw:items-center tw:gap-1.5"><KeyRound className="tw:size-3.5 tw:text-faint" />1. The enrollment configuration</h4>
        <p className="tw:text-muted">
          Agents need this server's <b>client configuration</b>: the server address, the certificate authority they trust,
          and the {info.org_name === 'root' ? '' : `“${info.org_name}” `}org's enrollment nonce (the shared secret).
          It was created with the server{info.org_name === 'root' ? '' : ' or org'}; every command below already contains it.
          Anyone who has it can enroll a computer to this server, so give it only to the people who deploy agents.
          Each agent then creates its own key the first time it starts.
        </p>
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <span className="tw:text-muted">Server:</span>
          {info.server_urls.map(u => <Badge key={u}><Mono>{u}</Mono></Badge>)}
          <span className="tw:text-faint tw:text-xs">SHA-256 {info.config_sha256.slice(0, 16)}…</span>
          <Button size="sm" variant="secondary" icon={<Download />} onClick={() => download('client.config.yaml')}>client.config.yaml</Button>
          <Button size="sm" variant="ghost" onClick={() => setShowConfig(v => !v)}>{showConfig ? 'Hide' : 'Show'}</Button>
        </div>
        {showConfig && <CodeBox text={info.client_config} full />}
      </div>

      <div className="tw:space-y-2">
        <h4 className="tw:font-semibold">2. Install the agent</h4>
        <Tabs value={tab} onValueChange={v => setTab(v as OsTab)} className="tw:px-0"
          tabs={[
            { value: 'windows', label: 'Windows' },
            { value: 'linux', label: 'Linux' },
            { value: 'macos', label: 'macOS' },
            { value: 'intune', label: 'Microsoft Intune' },
          ]} />
        {tab === 'windows' && <WindowsTab info={info} />}
        {tab === 'linux' && <UnixTab info={info} os="linux" />}
        {tab === 'macos' && <UnixTab info={info} os="macos" />}
        {tab === 'intune' && <IntuneTab info={info} />}
      </div>

      <div className="tw:space-y-1">
        <h4 className="tw:font-semibold">3. Check that it worked</h4>
        <p className="tw:text-muted">
          Within a minute the computer appears in the list above and on the dashboard under Recently seen.
          If it doesn't, check that it can reach <Mono>{info.server_urls[0]}</Mono> and see{' '}
          <a className="tw:underline" href={`${DOCS}/troubleshooting/clients/`} target="_blank" rel="noreferrer">Agent problems</a>.
        </p>
      </div>
    </div>
  );
}

function CodeBox({ text, full, label }: { text: string; full?: boolean; label?: string }) {
  return (
    <div className="tw:relative tw:rounded-md tw:border tw:border-line tw:bg-panel">
      {label && <div className="tw:px-3 tw:pt-1.5 tw:text-2xs tw:text-faint">{label}</div>}
      <pre className={cn('tw:px-3 tw:py-2 tw:pr-14 tw:font-mono tw:text-[12px] tw:whitespace-pre-wrap tw:break-all',
        full ? 'tw:max-h-72 tw:overflow-y-auto' : 'tw:max-h-[3.6em] tw:overflow-hidden')}>{text}</pre>
      <CopyButton text={text} className="tw:absolute tw:top-1.5 tw:right-1.5 tw:bg-panel tw:text-xs tw:px-1.5 tw:py-0.5 tw:border tw:border-line" />
    </div>
  );
}

function WindowsTab({ info }: { info: DeployInfo }) {
  return (
    <div className="tw:space-y-3">
      <p className="tw:text-muted">
        On the computer, open <b>PowerShell as administrator</b> and paste this command. It downloads the signed
        program{info.version ? ` (version ${info.version})` : ''} from GitHub, checks that it is signed by Atlant Security,
        and installs it as the <Mono>Atlantiraptor</Mono> service with your configuration.
      </p>
      <CodeBox label="PowerShell (as administrator)" text={info.commands.windows} />
      <p className="tw:text-muted">
        Or download the same installer as a script, for many computers, Group Policy, SCCM or an RMM tool. It works offline
        too if you put <Mono>Atlantiraptor.exe</Mono> next to it.
      </p>
      <div className="tw:flex tw:flex-wrap tw:gap-2">
        <Button size="sm" variant="secondary" icon={<Download />} onClick={() => download(info.intune.setup_file)}>{info.intune.setup_file}</Button>
      </div>
      <CodeBox label="Run the script" text={info.intune.install_command} />
      <CodeBox label="Uninstall" text={info.intune.uninstall_command} />
      <p className="tw:text-muted tw:text-xs">
        An MSI installer is also available: Atlant Security can build one for your server, or see{' '}
        <a className="tw:underline" href={`${DOCS}/deployment/clients/#the-msi-installer-recommended`} target="_blank" rel="noreferrer">Deploying agents</a>.
        The script and the MSI install the same way, so either can replace the other.
      </p>
    </div>
  );
}

function UnixTab({ info, os }: { info: DeployInfo; os: 'linux' | 'macos' }) {
  const file = os === 'linux' ? 'install-atlantiraptor-linux.sh' : 'install-atlantiraptor-macos.sh';
  const cmd = os === 'linux' ? info.commands.linux : info.commands.macos;
  return (
    <div className="tw:space-y-3">
      <p className="tw:text-muted">
        Put the <Mono>atlantiraptor</Mono> program for {os === 'linux' ? 'Linux' : 'macOS'} in a folder on the computer
        (Atlant Security provides it; it can also be built from source), open a terminal in that folder and paste this
        command. It installs the agent as {os === 'linux' ? <>the systemd service <Mono>atlantiraptor</Mono></> : <>the launchd daemon <Mono>com.atlantsecurity.atlantiraptor</Mono></>} with
        your configuration. Without the program in the folder it tries to download it from this release on GitHub.
      </p>
      <CodeBox label="Terminal (needs sudo)" text={cmd} />
      <div className="tw:flex tw:flex-wrap tw:gap-2">
        <Button size="sm" variant="secondary" icon={<Download />} onClick={() => download(file)}>{file}</Button>
      </div>
      <CodeBox label="Or run the script" text={`sudo sh ${file} --binary ./atlantiraptor`} />
      <CodeBox label="Uninstall" text={`sudo sh ${file} --uninstall`} />
      {os === 'macos' && (
        <p className="tw:text-muted tw:text-xs">
          Grant <Mono>/usr/local/atlantiraptor/atlantiraptor</Mono> Full Disk Access with an MDM profile (PPPC payload),
          otherwise the agent cannot read protected folders.
        </p>
      )}
    </div>
  );
}

function IntuneTab({ info }: { info: DeployInfo }) {
  const script = info.intune.setup_file;
  return (
    <div className="tw:space-y-3">
      <p className="tw:text-muted">
        Deploy the agent to Windows computers managed by Microsoft Intune as a <b>Win32 app</b>.
      </p>
      <div className="tw:rounded-md tw:bg-accent-soft tw:px-3 tw:py-2 tw:text-[13px]">
        <b>Intune needs two files from here:</b> the app package <Mono>Atlantiraptor-Intune.intunewin</Mono> (step 2)
        and the detection script <Mono>Detect-Atlantiraptor.ps1</Mono> (step 5). The installer{' '}
        <Mono>{script}</Mono> is already inside the package, so you don't upload it separately.
      </div>
      <ol className="tw:list-decimal tw:pl-5 tw:space-y-3 tw:text-muted">
        <li>In the <a className="tw:underline" href="https://intune.microsoft.com/" target="_blank" rel="noreferrer">Intune admin center <ExternalLink className="tw:inline tw:size-3" /></a>,
          go to <b>Apps &gt; Windows &gt; Create</b> and choose <b>Windows app (Win32)</b>.</li>
        <li>
          <div>App information: download the app package and select it as the <b>App package file</b>.
            Intune then shows <Mono>{script}</Mono> as its setup file. Name: <b>Atlantiraptor</b>, publisher: <b>Atlant Security</b>.</div>
          <div className="tw:mt-1.5">
            <Button size="sm" variant="primary" icon={<Download />} onClick={() => download('Atlantiraptor-Intune.intunewin')}>Atlantiraptor-Intune.intunewin</Button>
          </div>
        </li>
        <li>Program: copy these two commands. They run <Mono>{script}</Mono> from inside the package.
          <div className="tw:mt-1.5 tw:space-y-1.5">
            <CodeBox label="Install command" text={info.intune.install_command} />
            <CodeBox label="Uninstall command" text={info.intune.uninstall_command} />
          </div>
          Install behavior: <b>System</b>. Device restart behavior: <b>No specific action</b>.
        </li>
        <li>Requirements: operating system architecture <b>64-bit</b>, minimum Windows 10 1607.</li>
        <li>
          <div>Detection rules: choose <b>Use a custom detection script</b>, download the detection script and upload it as the
            <b> Script file</b>. Set <b>Run script as 32-bit process on 64-bit clients</b> to No. (Intune runs it to check
            whether the agent is installed.)</div>
          <div className="tw:mt-1.5">
            <Button size="sm" variant="secondary" icon={<Download />} onClick={() => download('Detect-Atlantiraptor.ps1')}>Detect-Atlantiraptor.ps1</Button>
          </div>
        </li>
        <li>Assignments: add your device group under <b>Required</b>, then create the app.</li>
      </ol>
      <div className="tw:text-muted tw:text-xs tw:space-y-1.5 tw:border-t tw:border-line tw:pt-3">
        <p>
          Not using a Win32 app? A simpler alternative is a platform script: add <Mono>{script}</Mono> under{' '}
          <b>Devices &gt; Scripts and remediations &gt; Platform scripts</b>, with <b>Run this script using the logged on
          credentials</b> = No and <b>Run script in 64 bit PowerShell Host</b> = Yes. Intune then can't report or uninstall
          the agent. Only this alternative needs the script on its own:
        </p>
        <Button size="xs" variant="secondary" icon={<Download />} onClick={() => download(script)}>{script}</Button>
        <p>
          An MSI from Atlant Security can also be added as a Line-of-business app. Details:{' '}
          <a className="tw:underline" href={`${DOCS}/deployment/intune/`} target="_blank" rel="noreferrer">Deploying with Intune</a>.
        </p>
      </div>
    </div>
  );
}
