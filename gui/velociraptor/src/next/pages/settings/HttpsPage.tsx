// Server settings > Address and certificate: serve the console at the
// customer's own host name (normally on port 443, so the address has no
// port) with a certificate browsers trust, uploaded or from Let's
// Encrypt. New settings run on trial and roll back unless confirmed;
// the original console address is never changed.
import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import {
  AlertTriangle, CheckCircle2, ExternalLink, FileKey2, Globe, Info, Lock, LifeBuoy, RotateCcw, ShieldCheck, Timer, Upload, XCircle,
} from 'lucide-react';
import {
  checkDns, daysLeft, fileToBase64, probe, redirectsToPublicUrl, useConsoleHttps, useConsoleHttpsAction,
  type ApplyRequest, type CertInfo, type CertMode, type HttpsUpload, type HttpsView,
} from '../../lib/consoleHttps';
import { ApiError } from '../../lib/api';
import {
  Badge, Button, Card, CardHeader, ConfirmDialog, EmptyState, Field, Input, Mono, Segmented, Skeleton, Switch, Textarea, cn,
} from '../../ui/primitives';

export default function HttpsPage() {
  const [poll, setPoll] = useState(false);
  const { data, isLoading, error } = useConsoleHttps(poll);
  const trial = !!data?.pending || data?.cert?.status === 'issuing';
  useEffect(() => setPoll(trial), [trial]);

  if (isLoading) return <div className="tw:p-6"><Skeleton className="tw:h-40" /></div>;
  if (error || !data) {
    return <EmptyState icon={<Lock />} title="Address and certificate settings are not available">{(error as Error)?.message}</EmptyState>;
  }
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4 tw:max-w-5xl">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Lock className="tw:size-5 tw:text-accent" />Address and certificate</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">
            Open the console at your own address, such as <Mono>https://console.example.com</Mono>, with no port number and no browser
            warning. Upload your certificate or let the server get a free one from Let's Encrypt.
          </p>
        </div>
        {!data.available
          ? <Card><div className="tw:p-4 tw:text-[13px] tw:flex tw:gap-2"><Info className="tw:size-4 tw:text-muted tw:shrink-0" />{data.unavailable_reason}</div></Card>
          : <>
            <StatusCard view={data} />
            <Editor key={`${data.active.updated ?? 0}-${data.pending?.expires ?? 0}`} view={data} />
          </>}
        <Recovery view={data} />
      </div>
    </div>
  );
}

const fmtDate = (s: number) => new Date(s * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });

function useCountdown(until?: number) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!until) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [until]);
  if (!until) return '';
  const s = Math.max(0, Math.round(until - now / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function StatusCard({ view }: { view: HttpsView }) {
  const act = useConsoleHttpsAction();
  const left = useCountdown(view.pending?.expires);
  const [reach, setReach] = useState<'unknown' | 'checking' | 'ok' | 'fail'>('unknown');
  const [forceKeep, setForceKeep] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const url = view.url;
  const certReady = view.cert?.status === 'ready';

  // Keep checking the new address from this browser while on trial.
  useEffect(() => {
    if (!url || !certReady) { setReach('unknown'); return; }
    let stop = false;
    const run = async () => {
      setReach(r => (r === 'ok' ? r : 'checking'));
      const ok = await probe(url);
      if (!stop) setReach(ok ? 'ok' : 'fail');
    };
    void run();
    const t = view.pending ? setInterval(run, 5000) : undefined;
    return () => { stop = true; if (t) clearInterval(t); };
  }, [url, certReady, view.pending]);

  const run = (action: 'confirm' | 'revert' | 'disable', done: string) => act.mutate({ action }, {
    onSuccess: () => { toast.success(done); setForceKeep(false); setDisabling(false); },
    onError: e => toast.error((e as Error).message),
  });

  if (!view.serving) {
    return (
      <Card>
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3 tw:px-4 tw:py-3 tw:text-[13px]">
          <Globe className="tw:size-4 tw:text-muted" />
          <span>The console is only at its original address.</span>
          <Mono className="tw:text-muted">{view.recovery_url}</Mono>
          {view.last_error && <span className="tw:basis-full tw:text-bad tw:text-xs">{view.last_error}</span>}
        </div>
      </Card>
    );
  }

  const info = view.cert?.info;
  return (
    <Card className={cn(view.pending && 'tw:border-warn')}>
      <CardHeader icon={view.pending ? <Timer /> : <ShieldCheck />}
        title={view.pending ? 'Trying the new settings' : 'The console is at your address'}
        subtitle={view.pending
          ? `They switch back by themselves in ${left} unless you keep them. Changed by ${view.pending.by}.`
          : view.active.updated ? `Set by ${view.active.updated_by} on ${fmtDate(view.active.updated)}` : undefined}
        actions={view.pending
          ? <div className="tw:flex tw:gap-2">
            <Button size="sm" variant="ghost" icon={<RotateCcw className="tw:size-3.5" />} loading={act.isPending && act.variables?.action === 'revert'}
              onClick={() => run('revert', 'Back to the previous settings')}>Undo</Button>
            <Button size="sm" variant="primary" icon={<CheckCircle2 className="tw:size-3.5" />} disabled={!certReady}
              loading={act.isPending && act.variables?.action === 'confirm'}
              onClick={() => (reach === 'ok' ? run('confirm', 'New address kept') : setForceKeep(true))}>Keep these settings</Button>
          </div>
          : <Button size="sm" variant="ghost" onClick={() => setDisabling(true)}>Turn off</Button>} />
      <div className="tw:px-4 tw:py-3 tw:space-y-3 tw:text-[13px]">
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2">
          <a href={url} target="_blank" rel="noreferrer" className="tw:font-mono tw:font-medium tw:text-accent tw:hover:underline tw:break-all tw:inline-flex tw:items-center tw:gap-1">
            {url}<ExternalLink className="tw:size-3.5" />
          </a>
          {view.cert?.status === 'issuing' && <Badge tone="info">Getting the certificate from Let's Encrypt…</Badge>}
          {view.cert?.status === 'failed' && <Badge tone="bad">Let's Encrypt failed</Badge>}
          {certReady && reach === 'checking' && <Badge>Checking from your browser…</Badge>}
          {certReady && reach === 'ok' && <Badge tone="ok"><CheckCircle2 className="tw:size-3" />Opens in your browser without a warning</Badge>}
          {certReady && reach === 'fail' && <Badge tone="warn"><AlertTriangle className="tw:size-3" />Your browser can't open it yet</Badge>}
        </div>
        {view.cert?.status === 'failed' && <p className="tw:text-xs tw:text-bad">{view.cert.error}</p>}
        {certReady && reach === 'fail' && (
          <p className="tw:text-xs tw:text-muted">
            Either the name doesn't point to this server from where you are, a firewall blocks the port, or the browser doesn't trust the
            certificate. Open the link to see the browser's own message.
          </p>
        )}
        {view.dns_error && <p className="tw:text-xs tw:text-warn">{view.dns_error}</p>}
        {view.dns && view.dns.length > 0 && <p className="tw:text-2xs tw:text-faint">{(view.pending?.settings ?? view.active).hostname} points to {view.dns.join(', ')}</p>}
        {info && <CertSummary info={info} />}
        {redirectsToPublicUrl(view.authenticator) && view.public_url && !view.public_url.startsWith(originOf(url)) && (
          <p className="tw:text-xs tw:text-warn tw:flex tw:gap-1.5">
            <AlertTriangle className="tw:size-3.5 tw:shrink-0 tw:mt-0.5" />
            <span>Sign-in uses {view.authenticator}, which returns to <Mono>{view.public_url}</Mono>. To sign in at the new address, set
              GUI.public_url to it in the server config, add its callback URL in your identity provider, and restart the server.</span>
          </p>
        )}
      </div>

      <ConfirmDialog open={forceKeep} onOpenChange={setForceKeep} title="Keep settings your browser couldn't test?"
        confirmLabel="Keep them anyway" loading={act.isPending} onConfirm={() => run('confirm', 'New address kept')}>
        This browser couldn't open {url}. That can be fine (for example if the name only works outside your office network), but if
        nobody can reach it, use the original address to change it again: {view.recovery_url}
      </ConfirmDialog>
      <ConfirmDialog open={disabling} onOpenChange={setDisabling} danger title="Stop serving the console at this address?"
        confirmLabel="Turn off" loading={act.isPending} onConfirm={() => run('disable', 'Turned off')}>
        People using {url} will need to use the original address, {view.recovery_url}. The certificate is removed from the server.
      </ConfirmDialog>
    </Card>
  );
}

function originOf(url?: string) {
  try {
    return url ? new URL(url).origin : '';
  } catch {
    return '';
  }
}

function CertSummary({ info }: { info: CertInfo }) {
  const days = daysLeft(info.not_after);
  return (
    <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-x-6 tw:gap-y-1 tw:text-xs tw:rounded-md tw:bg-canvas tw:border tw:border-line tw:p-3">
      <div><span className="tw:text-faint">Certificate for </span>{info.names.join(', ') || info.subject}</div>
      <div><span className="tw:text-faint">Issued by </span>{info.issuer}</div>
      <div>
        <span className="tw:text-faint">Valid until </span>{fmtDate(info.not_after)}
        <span className={cn('tw:ml-1', days < 14 ? 'tw:text-bad' : days < 30 ? 'tw:text-warn' : 'tw:text-faint')}>({days} days)</span>
      </div>
      <div>
        {info.trusted ? <span className="tw:text-ok">Trusted by browsers</span> : <span className="tw:text-warn">{info.trust_error}</span>}
        <span className="tw:text-faint"> · {info.key_algorithm}</span>
      </div>
    </div>
  );
}

interface Draft {
  hostname: string;
  port: string;
  mode: CertMode;
  redirect: boolean;
  email: string;
  bind: string;
  keep: boolean;
  source: 'pfx' | 'pem';
  pfx: File | null;
  pfxPassword: string;
  certPem: string;
  keyPem: string;
}

function Editor({ view }: { view: HttpsView }) {
  const act = useConsoleHttpsAction();
  const base = view.pending?.settings ?? view.active;
  const hasCert = base.mode === 'certificate' && !!base.cert_pem;
  const [d, setD] = useState<Draft>(() => ({
    hostname: base.hostname || '',
    port: String(base.port || 443),
    mode: base.mode || 'letsencrypt',
    redirect: base.enabled ? base.redirect_http : true,
    email: base.email || '',
    bind: base.bind_address || '',
    keep: hasCert,
    source: 'pfx',
    pfx: null, pfxPassword: '', certPem: '', keyPem: '',
  }));
  const [warnings, setWarnings] = useState<string | null>(null);
  const [dns, setDns] = useState<{ host: string; text: string; bad: boolean } | null>(null);
  const [advanced, setAdvanced] = useState(!!base.bind_address);
  const set = (p: Partial<Draft>) => setD(x => ({ ...x, ...p }));

  const port = Number(d.port);
  const portProblem = !Number.isInteger(port) || port < 1 || port > 65535 ? 'Enter a port between 1 and 65535.'
    : view.reserved_ports?.includes(port) ? `Port ${port} is already used by the server.` : '';
  const needsUpload = d.mode === 'certificate' && !(hasCert && d.keep);
  const uploadMissing = needsUpload && (d.source === 'pfx' ? !d.pfx : !d.certPem.trim() || !d.keyPem.trim());
  const preview = useMemo(() => {
    const h = d.hostname.trim().toLowerCase() || 'console.example.com';
    return `https://${h}${port === 443 || !port ? '' : `:${port}`}/`;
  }, [d.hostname, port]);

  const lookup = async () => {
    const host = d.hostname.trim();
    if (!host) return;
    try {
      const r = await checkDns(host);
      setDns(r.dns_error ? { host: r.hostname, text: r.dns_error, bad: true }
        : { host: r.hostname, text: `${r.hostname} points to ${(r.dns ?? []).join(', ')}`, bad: false });
    } catch (e) {
      setDns({ host, text: (e as Error).message, bad: true });
    }
  };

  const submit = async (confirm = false) => {
    let upload: HttpsUpload | undefined;
    if (needsUpload) {
      upload = d.source === 'pfx' && d.pfx
        ? { pfx_base64: await fileToBase64(d.pfx), pfx_password: d.pfxPassword }
        : { cert_pem: d.certPem, key_pem: d.keyPem };
    }
    const req: ApplyRequest = {
      action: 'apply', confirm,
      settings: {
        hostname: d.hostname, port, mode: d.mode, redirect_http: d.redirect,
        email: d.mode === 'letsencrypt' ? d.email : '', bind_address: advanced ? d.bind : '',
      },
      upload, keep_certificate: d.mode === 'certificate' && !needsUpload,
    };
    act.mutate(req, {
      onSuccess: () => {
        setWarnings(null);
        toast.success('New settings are on trial. Check the address, then keep them.');
      },
      onError: e => {
        const err = e as ApiError;
        if (err.status === 409 && !confirm) setWarnings(err.message);
        else toast.error(err.message, { duration: 12000 });
      },
    });
  };

  return (
    <Card>
      <CardHeader icon={<Globe />} title={view.serving ? 'Change the address or certificate' : 'Set up your address'}
        subtitle="Changes start at once, on trial. The original address keeps working whatever you do here." />
      <div className="tw:p-4 tw:space-y-4">
        <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-[1fr_120px] tw:gap-3">
          <Field label="Host name" required
            hint={<>Create a DNS record for it that points to this server first. The console will open at <Mono>{preview}</Mono></>}>
            <div className="tw:flex tw:gap-2">
              <Input value={d.hostname} placeholder="console.example.com" autoComplete="off" spellCheck={false}
                onChange={e => { set({ hostname: e.target.value }); setDns(null); }} onBlur={() => void lookup()} />
              <Button type="button" onClick={() => void lookup()} disabled={!d.hostname.trim()}>Check DNS</Button>
            </div>
          </Field>
          <Field label="Port" hint={port === 443 ? 'Standard: no port in the address' : 'The address will need :' + (d.port || '?')}>
            <Input inputMode="numeric" value={d.port} onChange={e => set({ port: e.target.value.replace(/[^0-9]/g, '') })} />
          </Field>
        </div>
        {dns && dns.host === d.hostname.trim().toLowerCase() && (
          <p className={cn('tw:text-xs tw:-mt-2', dns.bad ? 'tw:text-warn' : 'tw:text-muted')}>{dns.text}</p>
        )}
        {portProblem && <p className="tw:text-xs tw:text-bad tw:-mt-2">{portProblem}</p>}

        <div className="tw:space-y-2">
          <div className="tw:text-xs tw:font-medium">Certificate</div>
          <Segmented<CertMode> size="md" value={d.mode} onChange={mode => set({ mode })}
            options={[{ value: 'letsencrypt', label: "Let's Encrypt (free, automatic)" }, { value: 'certificate', label: 'Upload my certificate' }]} />
          {d.mode === 'letsencrypt'
            ? (
              <div className="tw:space-y-3 tw:pt-1">
                <p className="tw:text-xs tw:text-muted">
                  The server gets the certificate and renews it before it expires. Let's Encrypt must be able to reach this server from the
                  internet at the host name on port 443 (or port 80 with the redirect below).
                </p>
                <Field label="Contact email (optional)" hint="Let's Encrypt writes here if there is a problem with the certificate.">
                  <Input type="email" value={d.email} onChange={e => set({ email: e.target.value })} placeholder="it@example.com" />
                </Field>
              </div>
            )
            : (
              <div className="tw:space-y-3 tw:pt-1">
                {hasCert && (
                  <Switch checked={d.keep} onChange={keep => set({ keep })}
                    label={<>Keep the current certificate <span className="tw:text-faint">(for {base.hostname})</span></>} />
                )}
                {needsUpload && <>
                  <Segmented value={d.source} onChange={source => set({ source })}
                    options={[{ value: 'pfx', label: '.pfx / .p12 file' }, { value: 'pem', label: 'PEM files' }]} />
                  {d.source === 'pfx'
                    ? (
                      <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
                        <Field label="Certificate file" hint="Export it with its private key and the full chain.">
                          <FilePick accept=".pfx,.p12" file={d.pfx} onFile={pfx => set({ pfx })} />
                        </Field>
                        <Field label="File password">
                          <Input type="password" autoComplete="new-password" value={d.pfxPassword} onChange={e => set({ pfxPassword: e.target.value })} />
                        </Field>
                      </div>
                    )
                    : (
                      <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
                        <PemField label="Certificate (with the intermediate certificates)" value={d.certPem}
                          onChange={certPem => set({ certPem })} placeholder="-----BEGIN CERTIFICATE-----" accept=".pem,.crt,.cer" />
                        <PemField label="Private key" value={d.keyPem} onChange={keyPem => set({ keyPem })}
                          placeholder="-----BEGIN PRIVATE KEY-----" accept=".pem,.key" />
                      </div>
                    )}
                  <p className="tw:text-2xs tw:text-faint tw:flex tw:gap-1.5">
                    <FileKey2 className="tw:size-3.5 tw:shrink-0" />
                    The private key is stored encrypted on the server and is never shown again.
                  </p>
                </>}
              </div>
            )}
        </div>

        <Switch checked={d.redirect} onChange={redirect => set({ redirect })}
          label={<>Send <Mono>http://</Mono> visitors to <Mono>https://</Mono> <span className="tw:text-faint">(uses port 80)</span></>} />

        <div>
          <button type="button" className="tw:text-xs tw:text-accent tw:hover:underline" onClick={() => setAdvanced(a => !a)}>
            {advanced ? 'Hide advanced' : 'Advanced'}
          </button>
          {advanced && (
            <Field className="tw:mt-2 tw:max-w-sm" label="Listen address" hint="Leave empty to listen on all of this server's addresses.">
              <Input value={d.bind} onChange={e => set({ bind: e.target.value.trim() })} placeholder="all addresses" />
            </Field>
          )}
        </div>

        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-3 tw:pt-1">
          <Button variant="primary" icon={<ShieldCheck className="tw:size-3.5" />} loading={act.isPending && act.variables?.action === 'apply'}
            disabled={!d.hostname.trim() || !!portProblem || uploadMissing} onClick={() => void submit(false)}>
            {view.serving ? 'Apply and test' : 'Turn on and test'}
          </Button>
          <span className="tw:text-2xs tw:text-faint">Nothing is permanent until you choose to keep it.</span>
        </div>
      </div>

      <ConfirmDialog open={!!warnings} onOpenChange={v => !v && setWarnings(null)} title="Use this certificate anyway?"
        confirmLabel="Try it anyway" loading={act.isPending} onConfirm={() => void submit(true)}>
        {warnings}
      </ConfirmDialog>
    </Card>
  );
}

function FilePick({ accept, file, onFile }: { accept: string; file: File | null; onFile: (f: File | null) => void }) {
  return (
    <label className="tw:flex tw:items-center tw:gap-2 tw:h-8 tw:px-2.5 tw:rounded-md tw:border tw:border-dashed tw:border-line-strong tw:text-[13px] tw:cursor-pointer tw:hover:bg-hover">
      <Upload className="tw:size-3.5 tw:text-muted" />
      <span className={cn('tw:truncate', !file && 'tw:text-faint')}>{file ? file.name : 'Choose a file…'}</span>
      <input type="file" accept={accept} className="tw:sr-only" onChange={e => onFile(e.target.files?.[0] ?? null)} />
    </label>
  );
}

function PemField({ label, value, onChange, placeholder, accept }: {
  label: string; value: string; onChange: (v: string) => void; placeholder: string; accept: string;
}) {
  return (
    <div className="tw:space-y-1">
      <div className="tw:flex tw:items-center tw:justify-between tw:gap-2">
        <span className="tw:text-xs tw:font-medium">{label}</span>
        <label className="tw:text-2xs tw:text-accent tw:cursor-pointer tw:hover:underline">
          Load file
          <input type="file" accept={accept} className="tw:sr-only"
            onChange={async e => { const f = e.target.files?.[0]; if (f) onChange(await f.text()); }} />
        </label>
      </div>
      <Textarea rows={6} className="tw:font-mono tw:text-2xs" value={value} spellCheck={false}
        onChange={e => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}

function Recovery({ view }: { view: HttpsView }) {
  return (
    <Card>
      <CardHeader icon={<LifeBuoy />} title="If something goes wrong" />
      <div className="tw:px-4 tw:py-3 tw:text-xs tw:text-muted tw:space-y-1.5">
        <p>The console's original address always keeps working: <Mono>{view.recovery_url}</Mono>. Use it to undo or change these settings.</p>
        <p>New settings you don't keep switch back by themselves after 10 minutes, and a server restart also drops settings that weren't kept.</p>
        <p>On Linux, using ports 443 and 80 needs permission: run <Mono>setcap cap_net_bind_service=+ep</Mono> on the server binary, or add
          <Mono> AmbientCapabilities=CAP_NET_BIND_SERVICE</Mono> to its service. The page tells you if this is the problem.</p>
        <p className="tw:flex tw:gap-1.5"><XCircle className="tw:size-3.5 tw:shrink-0 tw:mt-0.5" />Endpoint agents are not affected: they keep
          connecting to the server's client port with their own certificate checks.</p>
        <p>Every change, confirmation and rollback is written to the audit log (<Mono>console_https_*</Mono>).</p>
      </div>
    </Card>
  );
}
