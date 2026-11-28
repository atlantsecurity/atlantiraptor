// AI triage settings: provider, model and API key. The key is stored as a
// server secret (encrypted, write-only, never shown again) that the
// console manages: admins paste the key, nothing else. Requests run on
// the server, so analysts can use AI triage without ever seeing the key.
import { useState } from 'react';
import { toast } from 'sonner';
import { KeyRound, Save, Sparkles } from 'lucide-react';
import * as api from '../../lib/api';
import { setServerMetadata, useServerMetadata } from '../../lib/queries';
import { runServerArtifact } from '../../lib/serverRun';
import { Badge, Button, Card, CardHeader, Input, Select } from '../../ui/primitives';

export type Provider = 'anthropic' | 'openai' | 'deepseek';

export const PROVIDERS: Record<Provider, { label: string; models: string[]; url: string; keyHint: string }> = {
  anthropic: {
    label: 'Claude (Anthropic)', url: 'https://api.anthropic.com/v1/messages', keyHint: 'sk-ant-…',
    models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-fable-5-2'],
  },
  openai: { label: 'OpenAI', url: 'https://api.openai.com/v1/chat/completions', keyHint: 'sk-…', models: ['gpt-6.2-astra'] },
  deepseek: { label: 'DeepSeek', url: 'https://api.deepseek.com/chat/completions', keyHint: 'sk-…', models: ['deepseek-v4-pro'] },
};

/** Name of the secret the console manages for this provider's key. */
export const managedSecretName = (p: Provider) => `atl-ai-${p}`;

/** The HTTP secret holding the key: fixed endpoint, key in the header the provider expects. */
export function managedSecret(p: Provider, key: string): Record<string, string> {
  // JSON strings are valid YAML, so a key can never break out of the value.
  const header = p === 'anthropic' ? `x-api-key: ${JSON.stringify(key)}` : `Authorization: ${JSON.stringify(`Bearer ${key}`)}`;
  return { url: PROVIDERS[p].url, method: 'POST', extra_headers: `${header}\n` };
}

async function saveKey(p: Provider, key: string): Promise<string> {
  const name = managedSecretName(p);
  await api.post('v1/AddSecret', { name, type_name: 'HTTP Secrets', secret: managedSecret(p, key) });
  // Every user who can run AI triage may use the key (never read it).
  await api.post('v1/ModifySecret', { type_name: 'HTTP Secrets', name, add_users: ['*'] });
  return name;
}

export function AiSettingsCard({ canAdmin }: { canAdmin: boolean }) {
  const meta = useServerMetadata();
  if (!meta.isFetched) return null;
  return <Form key={JSON.stringify(meta.data ?? {})} initial={meta.data ?? {}} canAdmin={canAdmin && meta.isSuccess}
    onSaved={() => meta.refetch()} />;
}

function Form({ initial, canAdmin, onSaved }: { initial: Record<string, string>; canAdmin: boolean; onSaved: () => void }) {
  const savedProvider = ((initial.atl_ai_provider as Provider) in PROVIDERS ? initial.atl_ai_provider : 'anthropic') as Provider;
  const [provider, setProvider] = useState<Provider>(savedProvider);
  const [model, setModel] = useState(initial.atl_ai_model || PROVIDERS[savedProvider].models[0]);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const p = PROVIDERS[provider];
  const savedSecret = initial.atl_ai_secret || '';
  const configured = !!savedSecret;
  // A key saved for this provider (by this card, or an HTTP secret set up by hand earlier, which keeps working).
  const haveKey = configured && provider === savedProvider;
  const legacy = haveKey && savedSecret !== managedSecretName(provider);
  const dirty = provider !== savedProvider || model.trim() !== (initial.atl_ai_model || '') || !!key.trim();

  const save = async () => {
    setBusy('save');
    try {
      const secret = key.trim() ? await saveKey(provider, key.trim()) : savedSecret;
      await setServerMetadata('atl_ai_provider', provider);
      await setServerMetadata('atl_ai_model', model.trim());
      await setServerMetadata('atl_ai_secret', secret);
      setKey('');
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
      const answer = String(r.rows[0]?.Summary ?? '') || r.logs.slice(-1)[0] || '';
      const status = Number(r.rows[0]?.Status ?? 0);
      if (status >= 200 && status < 300) toast.success(`AI answered: ${answer.slice(0, 200)}`);
      else toast.error(answer.slice(0, 300) || 'The AI request failed.');
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card>
      <CardHeader icon={<Sparkles />} title="AI triage"
        subtitle="Summaries of alerts, collections, full triage and cases from Claude, OpenAI or DeepSeek. Requests run on the server."
        actions={configured ? <Badge tone="ok" dot>On</Badge> : <Badge tone="neutral">Off</Badge>} />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-3">
          <label className="tw:block">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Provider</span>
            <Select value={provider} disabled={!canAdmin}
              onChange={e => { const v = e.target.value as Provider; setProvider(v); setModel(PROVIDERS[v].models[0]); }}>
              {(Object.keys(PROVIDERS) as Provider[]).map(k => <option key={k} value={k}>{PROVIDERS[k].label}</option>)}
            </Select>
          </label>
          <label className="tw:block">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Model</span>
            <Input value={model} onChange={e => setModel(e.target.value)} list="atl-ai-models" disabled={!canAdmin}
              className="tw:font-mono tw:text-xs" />
            <datalist id="atl-ai-models">{p.models.map(m => <option key={m} value={m} />)}</datalist>
          </label>
          <label className="tw:block tw:sm:col-span-2">
            <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">API key</span>
            <Input type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} disabled={!canAdmin}
              placeholder={haveKey ? 'Saved. Paste a new key to replace it' : p.keyHint} className="tw:font-mono tw:text-xs" />
            <span className="tw:mt-1 tw:flex tw:items-center tw:gap-1 tw:text-2xs tw:text-faint">
              <KeyRound className="tw:size-3" />Stored encrypted on the server and never shown again. Analysts can use it without seeing it.
            </span>
          </label>
        </div>
        {legacy && (
          <p className="tw:text-2xs tw:text-muted">
            Using the key in the secret <span className="tw:font-mono">{savedSecret}</span> set up earlier. Paste the key here to have the console manage it instead.
          </p>
        )}
        <p className="tw:text-2xs tw:text-faint">
          Each request sends at most 60,000 characters of the data being triaged to {p.label}, and the analyst sees exactly what will be sent before it goes.
          Check that your agreement with the provider covers endpoint data.
        </p>
        {!canAdmin && <p className="tw:text-2xs tw:text-warn">Only server admins can change these settings.</p>}
        <div className="tw:flex tw:justify-end tw:gap-1.5">
          <Button size="sm" variant="ghost" loading={busy === 'test'} disabled={!!busy || !configured || dirty}
            title={dirty ? 'Save first' : undefined} onClick={test}>Test</Button>
          <Button size="sm" variant="primary" icon={<Save className="tw:size-3.5" />} loading={busy === 'save'}
            disabled={!!busy || !canAdmin || !dirty || !model.trim() || (!haveKey && !key.trim())} onClick={save}>Save</Button>
        </div>
      </div>
    </Card>
  );
}
