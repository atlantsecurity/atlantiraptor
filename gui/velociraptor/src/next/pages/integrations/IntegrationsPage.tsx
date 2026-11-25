// Integrations: forward alerts to chat, email and SIEMs, and import
// indicators from MISP. Credentials stay in server-side secrets.
import { useState } from 'react';
import { Link, useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import { FlaskConical, Plug, Power, PowerOff, Save, Download } from 'lucide-react';
import { runArtifact, usePermission, useSecretDefinitions } from '../../lib/queries';
import { runServerArtifact } from '../../lib/serverRun';
import { Badge, Button, Card, CardHeader, Input, Select } from '../../ui/primitives';
import { IOC_PREFILL_KEY } from '../ioc/IocSweepPage';
import { INTEGRATIONS, secretTypeOf, type Integration } from './catalog';
import { useServerMonitoring } from './monitoring';

export default function IntegrationsPage() {
  const monitoring = useServerMonitoring();
  const canAdmin = usePermission('server_admin');
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div className="tw:flex tw:flex-wrap tw:items-end tw:gap-3">
          <div className="tw:flex-1">
            <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><Plug className="tw:size-5 tw:text-accent" />Integrations</h1>
            <p className="tw:text-xs tw:text-muted tw:mt-1">
              Send alerts to the tools your team already uses, and pull indicators in. Credentials live in <Link to="/secrets" className="tw:text-accent tw:hover:underline">Secrets</Link>, never on this page.
            </p>
          </div>
          <TestButton />
        </div>
        {!canAdmin && <div className="tw:text-xs tw:text-warn">Only server admins can change integrations.</div>}
        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          {INTEGRATIONS.map(i => (
            // Remount when the stored settings arrive or change, so the form shows them.
            <IntegrationCard key={`${i.id}-${monitoring.loaded}-${JSON.stringify(monitoring.specOf(i.artifact))}`}
              integration={i} monitoring={monitoring} canAdmin={canAdmin} />
          ))}
        </div>
      </div>
    </div>
  );
}

function TestButton() {
  const [busy, setBusy] = useState(false);
  return (
    <Button variant="secondary" icon={<FlaskConical className="tw:size-3.5" />} loading={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await runArtifact('server', 'Server.Alerts.Test', { Level: 'critical' });
          toast.success('Test alert raised. Enabled integrations should receive it within a few seconds, and it shows on the dashboard.');
        } catch (e) {
          toast.error((e as Error).message);
        } finally {
          setBusy(false);
        }
      }}>Send test alert</Button>
  );
}

function IntegrationCard({ integration: it, monitoring, canAdmin }: {
  integration: Integration; monitoring: ReturnType<typeof useServerMonitoring>; canAdmin: boolean;
}) {
  const history = useHistory();
  const { data: defs = [] } = useSecretDefinitions();
  const current = it.mode === 'forwarder' ? monitoring.specOf(it.artifact) : null;
  const enabled = !!current;
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(it.fields.map(f => [f.key, current?.[f.key] ?? f.initial])));
  const [busy, setBusy] = useState(false);
  const missingSecret = !values.Secret;

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      toast.success(ok);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const importMisp = () => run(async () => {
    const r = await runServerArtifact(it.artifact, values, { timeoutMs: 180_000 });
    if (!r.rows.length) throw new Error('MISP returned no matching indicators.');
    const text = r.rows.map(x => [x.Type, x.Value, x.Note].map(v => String(v ?? '').replace(/[\r\n,]+/g, ' ')).join(',')).join('\n');
    sessionStorage.setItem(IOC_PREFILL_KEY, text);
    history.push('/ioc');
  }, 'Indicators imported. Review them, then start the sweep.');

  return (
    <Card>
      <CardHeader icon={it.icon} title={it.title} subtitle={it.description}
        actions={it.mode === 'forwarder' && (enabled ? <Badge tone="ok" dot>On</Badge> : <Badge tone="neutral">Off</Badge>)} />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3">
          {it.fields.map(f => {
            const type = secretTypeOf(f, values);
            const names = defs.find(d => d.type_name === type)?.secret_names ?? [];
            return (
              <label key={f.key} className="tw:block">
                <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">{f.label}</span>
                {f.kind === 'select' ? (
                  <Select value={values[f.key]} onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))}>
                    {f.options?.map(o => <option key={o} value={o}>{o}</option>)}
                  </Select>
                ) : f.kind === 'secret' ? (
                  <Select value={values[f.key]} onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))}>
                    <option value="">{names.length ? 'Choose a secret' : `No ${type} secrets yet`}</option>
                    {names.map(n => <option key={n} value={n}>{n}</option>)}
                  </Select>
                ) : (
                  <Input value={values[f.key]} onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))} />
                )}
                {f.kind === 'secret' && (
                  <Link to={`/secrets/${encodeURIComponent(type)}`} className="tw:block tw:mt-1 tw:text-2xs tw:text-accent tw:hover:underline">Manage {type} secrets</Link>
                )}
                {f.help && <span className="tw:block tw:mt-1 tw:text-2xs tw:text-muted">{f.help}</span>}
              </label>
            );
          })}
        </div>
        <p className="tw:text-2xs tw:text-faint">{it.setup}</p>
        <div className="tw:flex tw:flex-wrap tw:justify-end tw:gap-1.5">
          {it.mode === 'import' ? (
            <Button size="sm" variant="primary" icon={<Download className="tw:size-3.5" />} loading={busy}
              disabled={missingSecret} onClick={importMisp}>Import into IOC sweep</Button>
          ) : <>
            {enabled && (
              <Button size="sm" variant="ghost" icon={<PowerOff className="tw:size-3.5" />} disabled={busy || !canAdmin}
                onClick={() => run(() => monitoring.remove(it.artifact), `${it.title} turned off`)}>Turn off</Button>
            )}
            <Button size="sm" variant="primary" icon={enabled ? <Save className="tw:size-3.5" /> : <Power className="tw:size-3.5" />}
              loading={busy} disabled={missingSecret || !canAdmin || !monitoring.loaded}
              onClick={() => run(() => monitoring.upsert(it.artifact, values), enabled ? 'Settings saved' : `${it.title} turned on`)}>
              {enabled ? 'Save' : 'Turn on'}
            </Button>
          </>}
        </div>
      </div>
    </Card>
  );
}
