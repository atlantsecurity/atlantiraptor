// "Connect a SIEM": creates a key from a role preset in one step, then
// shows the settings to paste into the SIEM, the CA certificate to
// download, where to put it, and a live test of the new key.
import { useState } from 'react';
import { toast } from 'sonner';
import { CheckCircle2, Download, Plug, XCircle } from 'lucide-react';
import {
  downloadCaCertificate, testApiKey, useCreateApiKey, type ConnectionInfo, type CreatedKey, type TestResult,
} from '../../lib/apikeys';
import { Badge, Button, CopyButton, Dialog, Field, Input, Mono, Segmented, Select, cn } from '../../ui/primitives';

type Preset = 'respond' | 'triage' | 'read';
type Where = 'docker' | 'remote';

const PRESETS: Record<Preset, { label: string; roles: string[]; blurb: string }> = {
  respond: { label: 'Full response', roles: ['reader', 'responder'], blurb: 'Read alerts and hosts, run triage and response actions (quarantine, kill, delete). Live actions need a reason and follow your approval policy.' },
  triage: { label: 'Triage only', roles: ['reader', 'hunter'], blurb: 'Read alerts and hosts and run triage collections. Response actions are refused.' },
  read: { label: 'Read only', roles: ['reader'], blurb: 'Read alerts, hosts, hunts and cases. Nothing is run on endpoints.' },
};

const CA_IN_CONTAINER = '/etc/atlantiraptor/ca.pem';

interface Props { open: boolean; onOpenChange: (v: boolean) => void; connection?: ConnectionInfo }

export function ConnectSiemDialog({ open, onOpenChange, connection }: Props) {
  const create = useCreateApiKey();
  const [name, setName] = useState('Atlant SIEM');
  const [preset, setPreset] = useState<Preset>('respond');
  const [ttl, setTtl] = useState('365');
  const [where, setWhere] = useState<Where>('docker');
  const [created, setCreated] = useState<CreatedKey | null>(null);

  const close = (v: boolean) => {
    if (!v) { setCreated(null); create.reset(); }
    onOpenChange(v);
  };
  const submit = () => create.mutate(
    { name: name.trim(), roles: PRESETS[preset].roles, ttl_days: Number(ttl) },
    { onSuccess: setCreated, onError: e => toast.error((e as Error).message) });

  return (
    <Dialog open={open} onOpenChange={close} width={760}
      title={created ? 'Your SIEM settings' : 'Connect a SIEM'}
      description={created
        ? 'The key is shown only now. Copy the settings before closing this window.'
        : 'Creates an API key for the SIEM and gives you everything to paste into it.'}
      footer={created
        ? <Button variant="primary" onClick={() => close(false)}>Done, I have copied the settings</Button>
        : <>
            <Button variant="secondary" onClick={() => close(false)}>Cancel</Button>
            <Button variant="primary" loading={create.isPending} disabled={!name.trim()} onClick={submit}>Create key and show settings</Button>
          </>}>
      {created
        ? <Settings created={created} connection={connection} where={where} />
        : (
          <div className="tw:space-y-4">
            <Field label="Name" required><Input value={name} onChange={e => setName(e.target.value)} /></Field>
            <Field label="What may the SIEM do?">
              <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-3 tw:gap-2">
                {(Object.keys(PRESETS) as Preset[]).map(p => (
                  <button key={p} type="button" onClick={() => setPreset(p)}
                    className={cn('tw:text-left tw:rounded-md tw:border tw:p-2.5 tw:space-y-1',
                      preset === p ? 'tw:border-accent tw:bg-accent-soft' : 'tw:border-line tw:hover:bg-hover')}>
                    <div className="tw:text-[13px] tw:font-medium">{PRESETS[p].label}{p === 'respond' && <Badge tone="accent" className="tw:ml-1.5">Recommended</Badge>}</div>
                    <div className="tw:text-xs tw:text-muted">{PRESETS[p].blurb}</div>
                  </button>
                ))}
              </div>
            </Field>
            <div className="tw:flex tw:flex-wrap tw:gap-4">
              <Field label="Where does the SIEM run?">
                <Segmented<Where> value={where} onChange={setWhere}
                  options={[{ value: 'docker', label: 'Docker on this computer' }, { value: 'remote', label: 'Another machine' }]} />
              </Field>
              <Field label="Key expires">
                <Select value={ttl} onChange={e => setTtl(e.target.value)}>
                  <option value="90">In 90 days</option>
                  <option value="365">In a year</option>
                  <option value="0">Never</option>
                </Select>
              </Field>
            </div>
          </div>
        )}
    </Dialog>
  );
}

function Settings({ created, connection, where }: { created: CreatedKey; connection?: ConnectionInfo; where: Where }) {
  const [test, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const certName = connection?.cert_name || 'VelociraptorServer';
  const port = connection?.port || Number(window.location.port) || 8889;
  const env = [
    `ATLANT_ATLANTIRAPTOR_URL=https://${certName}:${port}`,
    `ATLANT_ATLANTIRAPTOR_KEY=${created.token}`,
    `ATLANT_ATLANTIRAPTOR_CA_FILE=${CA_IN_CONTAINER}`,
    `ATLANT_ATLANTIRAPTOR_CONSOLE_URL=${window.location.origin}`,
  ].join('\n');
  const hostsLine = where === 'docker'
    ? `extra_hosts:\n  - "${certName}:host-gateway"`
    : `<this server's IP address>  ${certName}`;

  return (
    <div className="tw:space-y-4 tw:text-[13px]">
      <Step n={1} title="Paste these settings into the SIEM's .env file">
        <CodeBlock text={env} />
      </Step>

      <Step n={2} title="Download the CA certificate and put it next to the SIEM">
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3">
          <Button variant="secondary" icon={<Download className="tw:size-3.5" />} disabled={connection && !connection.has_ca}
            onClick={() => downloadCaCertificate().catch(e => toast.error((e as Error).message))}>Download CA certificate (.pem)</Button>
          <span className="tw:text-xs tw:text-muted">Public certificate only. It lets the SIEM verify this server; TLS checking stays on.</span>
        </div>
        <p className="tw:text-xs tw:text-muted">
          {where === 'docker'
            ? <>Save it as <Mono>var/atlantiraptor/ca.pem</Mono> in the SIEM folder. The SIEM's compose file mounts that folder at <Mono>/etc/atlantiraptor</Mono>.</>
            : <>Save it on the SIEM machine and set <Mono>ATLANT_ATLANTIRAPTOR_CA_FILE</Mono> to its path there.</>}
        </p>
      </Step>

      <Step n={3} title={`Make the name ${certName} point at this server`}>
        <p className="tw:text-xs tw:text-muted">
          This server's certificate is issued to <Mono>{certName}</Mono>{connection?.cert_names && connection.cert_names.length > 1 ? <> (also {connection.cert_names.slice(1).join(', ')})</> : null},
          so the SIEM must connect using that name.{' '}
          {where === 'docker'
            ? <>Add this to the SIEM's <Mono>api</Mono> and <Mono>worker</Mono> services in <Mono>docker-compose.yml</Mono> (already done in Atlant SIEM):</>
            : <>Add this line to the SIEM machine's hosts file:</>}
        </p>
        <CodeBlock text={hostsLine} />
        {where === 'remote' && connection?.loopback_only && (
          <p className="tw:text-xs tw:text-warn">
            This server only listens on {connection.bind_address}, so another machine can't reach it yet. Set <Mono>GUI.bind_address</Mono> to
            a reachable address in the server config and restart it.
          </p>
        )}
      </Step>

      <Step n={4} title="Restart the SIEM">
        {where === 'docker'
          ? <CodeBlock text="docker compose up -d api worker" />
          : <p className="tw:text-xs tw:text-muted">Restart the SIEM's services so they read the new settings.</p>}
      </Step>

      <Step n={5} title="Test the key">
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3">
          <Button variant="secondary" icon={<Plug className="tw:size-3.5" />} loading={testing}
            onClick={async () => { setTesting(true); setTest(await testApiKey(created.token)); setTesting(false); }}>Test connection</Button>
          {test && (
            <span className={cn('tw:flex tw:items-center tw:gap-1.5 tw:text-xs', test.ok ? 'tw:text-ok' : 'tw:text-bad')}>
              {test.ok ? <CheckCircle2 className="tw:size-4" /> : <XCircle className="tw:size-4" />}{test.message}
            </span>
          )}
        </div>
        <p className="tw:text-xs tw:text-muted">Calls the API with the new key from this browser. Once the SIEM is restarted, its own connection check confirms the network path and certificate.</p>
      </Step>
    </div>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="tw:flex tw:gap-3">
      <div className="tw:size-6 tw:shrink-0 tw:rounded-full tw:bg-accent-soft tw:text-accent tw:text-xs tw:font-semibold tw:flex tw:items-center tw:justify-center">{n}</div>
      <div className="tw:flex-1 tw:min-w-0 tw:space-y-1.5">
        <div className="tw:font-medium">{title}</div>
        {children}
      </div>
    </div>
  );
}

function CodeBlock({ text }: { text: string }) {
  return (
    <div className="tw:relative tw:rounded-md tw:border tw:border-line tw:bg-sunken">
      <pre className="tw:p-3 tw:pr-10 tw:text-[12px] tw:overflow-x-auto tw:whitespace-pre"><code>{text}</code></pre>
      <div className="tw:absolute tw:top-2 tw:right-2"><CopyButton text={text} /></div>
    </div>
  );
}
