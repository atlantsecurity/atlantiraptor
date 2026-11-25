// AI triage settings: provider, model and the HTTP secret that holds the
// endpoint and API key. Stored in server metadata (admin only); the key
// itself only ever lives in the secret.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { toast } from 'sonner';
import { Save, Sparkles } from 'lucide-react';
import { setServerMetadata, useSecretDefinitions, useServerMetadata } from '../../lib/queries';
import { runServerArtifact } from '../../lib/serverRun';
import { Badge, Button, Card, CardHeader, Input, Select } from '../../ui/primitives';

type Provider = 'anthropic' | 'openai' | 'deepseek';

const PROVIDERS: Record<Provider, { label: string; model: string; url: string; header: string }> = {
  anthropic: { label: 'Claude (Anthropic)', model: 'claude-opus-5-5', url: 'https://api.anthropic.com/v1/messages', header: 'x-api-key: <your key>' },
  openai: { label: 'OpenAI', model: 'gpt-6.2-astra', url: 'https://api.openai.com/v1/chat/completions', header: 'Authorization: Bearer <your key>' },
  deepseek: { label: 'DeepSeek', model: 'deepseek-v4-pro', url: 'https://api.deepseek.com/chat/completions', header: 'Authorization: Bearer <your key>' },
};

export function AiSettingsCard({ canAdmin }: { canAdmin: boolean }) {
  const meta = useServerMetadata();
  const { data: defs = [] } = useSecretDefinitions();
  const secrets = defs.find(d => d.type_name === 'HTTP Secrets')?.secret_names ?? [];
  if (!meta.isFetched) return null;
  return <Form key={JSON.stringify(meta.data ?? {})} initial={meta.data ?? {}} secrets={secrets} canAdmin={canAdmin && meta.isSuccess}
    onSaved={() => meta.refetch()} />;
}

function Form({ initial, secrets, canAdmin, onSaved }: {
  initial: Record<string, string>; secrets: string[]; canAdmin: boolean; onSaved: () => void;
}) {
  const [provider, setProvider] = useState<Provider>((initial.atl_ai_provider as Provider) || 'anthropic');
  const [model, setModel] = useState(initial.atl_ai_model || PROVIDERS[(initial.atl_ai_provider as Provider) || 'anthropic'].model);
  const [secret, setSecret] = useState(initial.atl_ai_secret || '');
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const p = PROVIDERS[provider];
  const configured = !!initial.atl_ai_secret;

  const save = async () => {
    setBusy('save');
    try {
      await setServerMetadata('atl_ai_provider', provider);
      await setServerMetadata('atl_ai_model', model.trim());
      await setServerMetadata('atl_ai_secret', secret);
      toast.success('AI triage settings saved');
      onSaved();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy('test');
    try {
      const r = await runServerArtifact('Server.AI.Triage', {
        Task: 'Connectivity test: reply with one short sentence confirming you received this.',
        Context: 'No investigation data. This is a test.',
      }, { timeoutMs: 120_000 });
      const answer = String(r.rows[0]?.Summary ?? '');
      if (/^Error from/.test(answer)) toast.error(answer.slice(0, 300));
      else toast.success(`AI answered: ${answer.slice(0, 200)}`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <CardHeader icon={<Sparkles />} title="AI triage"
        subtitle="Summaries of alerts, collections and cases from Claude, OpenAI or DeepSeek. Requests run on the server."
        actions={configured ? <Badge tone="ok" dot>Configured</Badge> : <Badge tone="neutral">Off</Badge>} />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-3 tw:gap-3">
          <label className="tw:block">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Provider</span>
            <Select value={provider} onChange={e => { const v = e.target.value as Provider; setProvider(v); setModel(PROVIDERS[v].model); }}>
              {(Object.keys(PROVIDERS) as Provider[]).map(k => <option key={k} value={k}>{PROVIDERS[k].label}</option>)}
            </Select>
          </label>
          <label className="tw:block">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Model</span>
            <Input value={model} onChange={e => setModel(e.target.value)} className="tw:font-mono tw:text-xs" />
          </label>
          <label className="tw:block">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Secret with the API key</span>
            <Select value={secret} onChange={e => setSecret(e.target.value)}>
              <option value="">{secrets.length ? 'Choose a secret' : 'No HTTP Secrets yet'}</option>
              {secrets.map(n => <option key={n} value={n}>{n}</option>)}
            </Select>
            <Link to={`/secrets/${encodeURIComponent('HTTP Secrets')}`} className="tw:block tw:mt-1 tw:text-2xs tw:text-accent tw:hover:underline">Manage HTTP Secrets</Link>
          </label>
        </div>
        <p className="tw:text-2xs tw:text-faint">
          Create an HTTP Secrets secret with url <span className="tw:font-mono">{p.url}</span>, method POST, and in extra_headers <span className="tw:font-mono">{p.header}</span>.
          Each triage sends at most 60,000 characters of the data you are looking at to {p.label}, and shows you what it will send first.
        </p>
        {!canAdmin && <p className="tw:text-2xs tw:text-warn">Only server admins can change these settings.</p>}
        <div className="tw:flex tw:justify-end tw:gap-1.5">
          <Button size="sm" variant="ghost" loading={busy === 'test'} disabled={!!busy || !configured} onClick={test}>Test</Button>
          <Button size="sm" variant="primary" icon={<Save className="tw:size-3.5" />} loading={busy === 'save'}
            disabled={!!busy || !canAdmin || !secret || !model.trim()} onClick={save}>Save</Button>
        </div>
      </div>
    </Card>
  );
}
