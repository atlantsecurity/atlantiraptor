// Offline collector builder: pick artifacts and where the results go,
// and the server builds a standalone collector program (a server
// collection of Server.Utils.CreateCollector). The program is then
// downloaded from that collection's Uploaded files.
import { useMemo, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { AlertTriangle, Briefcase, ChevronDown, ChevronRight, HardDriveDownload, Lock, Package, Settings2 } from 'lucide-react';
import * as api from '../../lib/api';
import { useArtifactDefinitions, useCollectArtifact } from '../../lib/queries';
import { Button, Dialog, Field, Input, Segmented, Select, Switch, Textarea } from '../../ui/primitives';
import { ArtifactPicker } from '../hunts/ArtifactPicker';
import { ArtifactParams } from '../hunts/NewHuntDialog';
import {
  COLLECTOR_OS, TARGET_FIELDS, collectorProblems, collectorRequest, defaultCollectorForm,
  type CollectorEncryption, type CollectorForm, type CollectorTarget,
} from './offlineCollector';

const TARGET_LABEL: Record<CollectorTarget, string> = {
  ZIP: 'Zip file next to the collector', S3: 'Amazon S3 bucket', GCS: 'Google Cloud Storage bucket',
  Azure: 'Azure blob container', SMBShare: 'Windows (SMB) share', SFTP: 'SFTP server',
};

// The agent binary embedded in the collector, per OS.
const TOOL_FOR_OS: Record<string, string> = {
  Windows: 'VelociraptorWindows', WindowsArm64: 'VelociraptorWindowsArm64', Linux: 'VelociraptorLinux',
  MacOS: 'VelociraptorCollector', MacOSArm: 'VelociraptorCollector', Generic: 'VelociraptorCollector',
};

interface ToolInfo { name?: string; url?: string; filename?: string; version?: string; hash?: string }

function useTool(name: string) {
  return useQuery({
    queryKey: ['tool', name],
    queryFn: ({ signal }) => api.get<ToolInfo>('v1/GetToolInfo', { name }, signal),
    retry: false,
  });
}

export function OfflineCollectorDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const history = useHistory();
  const [form, setForm] = useState<CollectorForm>(defaultCollectorForm);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const { data: defs } = useArtifactDefinitions(form.artifacts);
  const tool = useTool(TOOL_FOR_OS[form.os]);
  const collect = useCollectArtifact();
  const problems = useMemo(() => collectorProblems(form), [form]);
  const patch = (p: Partial<CollectorForm>) => setForm(f => ({ ...f, ...p }));

  const toggle = (name: string) => setForm(f => {
    if (f.artifacts.includes(name)) {
      const parameters = { ...f.parameters };
      delete parameters[name];
      return { ...f, artifacts: f.artifacts.filter(a => a !== name), parameters };
    }
    setExpanded(name);
    return { ...f, artifacts: [...f.artifacts, name] };
  });

  const setParam = (artifact: string, key: string, value: string) => setForm(f => {
    const def = defs?.get(artifact)?.parameters?.find(p => p.name === key);
    const current = { ...(f.parameters[artifact] ?? {}) };
    if (def && (def.default ?? '') === value) delete current[key];
    else current[key] = value;
    return { ...f, parameters: { ...f.parameters, [artifact]: current } };
  });

  const build = () => {
    collect.mutate({ ...collectorRequest(form), client_id: 'server' }, {
      onSuccess: r => {
        toast.success('Building the collector. Download it from Uploaded files when the collection finishes.');
        onOpenChange(false);
        if (r?.flow_id) history.push(`/collected/server/${r.flow_id}/files`);
      },
      onError: e => toast.error((e as Error).message),
    });
  };

  const toolMissing = tool.isSuccess && !(tool.data?.url || tool.data?.filename || tool.data?.hash);

  return (
    <Dialog open={open} onOpenChange={onOpenChange} width={1180}
      title={<span className="tw:flex tw:items-center tw:gap-2"><Briefcase className="tw:size-4 tw:text-accent" />Build an offline collector</span>}
      description="A standalone program that collects the chosen artifacts on a machine without an agent, then saves or uploads the results."
      footer={<>
        {problems.length > 0 && <span className="tw:mr-auto tw:text-xs tw:text-muted">{problems[0]}</span>}
        <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
        <Button variant="primary" icon={<HardDriveDownload className="tw:size-3.5" />} disabled={problems.length > 0}
          loading={collect.isPending} onClick={build}>Build collector</Button>
      </>}>
      <div className="tw:flex tw:gap-5 tw:h-[min(640px,calc(100vh-220px))]">
        <div className="tw:w-[360px] tw:shrink-0 tw:border tw:border-line tw:rounded-lg tw:flex tw:flex-col tw:min-h-0 tw:overflow-hidden">
          <ArtifactPicker scope="client" selected={form.artifacts} onToggle={i => toggle(i.artifact.name)} />
        </div>

        <div className="tw:flex-1 tw:min-w-0 tw:overflow-y-auto tw:space-y-6 tw:pr-1">
          <section className="tw:space-y-3">
            <Heading icon={<Package />} title="Target machine" />
            <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
              <Field label="Operating system">
                <Select value={form.os} onChange={e => patch({ os: e.target.value as CollectorForm['os'] })}>
                  {COLLECTOR_OS.map(o => <option key={o} value={o}>{o}</option>)}
                </Select>
              </Field>
              <Field label="Embedded agent binary" hint={`Tool ${TOOL_FOR_OS[form.os]}`}>
                <div className="tw:text-xs tw:py-1.5 tw:break-all">
                  {tool.isLoading ? 'Checking…' : toolMissing
                    ? <span className="tw:text-warn">Not available yet; the server downloads it while building.</span>
                    : tool.data?.filename || tool.data?.url || 'Unknown'}
                </div>
              </Field>
            </div>
          </section>

          <section className="tw:space-y-2">
            <Heading icon={<Package />} title="Artifacts" hint={form.artifacts.length ? `${form.artifacts.length} selected` : 'Pick artifacts on the left'} />
            {form.artifacts.length === 0 && (
              <div className="tw:rounded-lg tw:border tw:border-dashed tw:border-line-strong tw:p-6 tw:text-center tw:text-xs tw:text-faint">
                Search and select the artifacts the collector should gather, for example Windows.KapeFiles.Targets.
              </div>
            )}
            {form.artifacts.map(name => (
              <ArtifactParams key={name} name={name} def={defs?.get(name)}
                values={form.parameters[name] ?? {}}
                expanded={expanded === name}
                onToggle={() => setExpanded(expanded === name ? null : name)}
                onChange={(k, v) => setParam(name, k, v)}
                onReset={() => setForm(f => { const p = { ...f.parameters }; delete p[name]; return { ...f, parameters: p }; })}
                onRemove={() => toggle(name)} />
            ))}
          </section>

          <section className="tw:space-y-3">
            <Heading icon={<HardDriveDownload />} title="Where the results go" />
            <Field label="Destination">
              <Select value={form.target} onChange={e => patch({ target: e.target.value as CollectorTarget, targetArgs: {} })}>
                {(Object.keys(TARGET_FIELDS) as CollectorTarget[]).map(t => <option key={t} value={t}>{TARGET_LABEL[t]}</option>)}
              </Select>
            </Field>
            {TARGET_FIELDS[form.target].length > 0 && (
              <>
                <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
                  {TARGET_FIELDS[form.target].map(f => (
                    <Field key={f.key} label={f.label} required={f.required} className={f.multiline ? 'tw:md:col-span-2' : undefined}>
                      {f.multiline
                        ? <Textarea rows={4} value={form.targetArgs[f.key] ?? ''} placeholder={f.placeholder} className="tw:font-mono tw:text-xs"
                          onChange={e => patch({ targetArgs: { ...form.targetArgs, [f.key]: e.target.value } })} />
                        : <Input type={f.secret ? 'password' : 'text'} autoComplete="off" value={form.targetArgs[f.key] ?? ''} placeholder={f.placeholder}
                          onChange={e => patch({ targetArgs: { ...form.targetArgs, [f.key]: e.target.value } })} />}
                    </Field>
                  ))}
                </div>
                <div className="tw:flex tw:gap-2 tw:rounded-md tw:border tw:border-warn/40 tw:bg-warn-soft tw:p-2.5 tw:text-xs tw:text-warn">
                  <AlertTriangle className="tw:size-4 tw:shrink-0" />
                  These credentials are built into the collector program. Anyone who has the program can read them, so give them write-only access to this one location.
                </div>
                <Switch checked={form.deleteAtExit} onChange={v => patch({ deleteAtExit: v })}
                  label="Delete the local copy after uploading (there is no check that the upload worked)" />
              </>
            )}
          </section>

          <section className="tw:space-y-3">
            <Heading icon={<Lock />} title="Encryption" />
            <Segmented size="md" value={form.encryption} onChange={v => patch({ encryption: v as CollectorEncryption })} options={[
              { value: 'None', label: 'None' }, { value: 'X509', label: 'Certificate' }, { value: 'Password', label: 'Password' },
            ]} />
            {form.encryption === 'X509' && (
              <Field label="Public key certificate (PEM)" hint="Leave empty to use this server's certificate, so only this server can open the collection.">
                <Textarea rows={4} className="tw:font-mono tw:text-xs" value={form.publicKey} onChange={e => patch({ publicKey: e.target.value })} />
              </Field>
            )}
            {form.encryption === 'Password' && (
              <Field label="Password" required hint="Needed to open the zip. It is stored inside the collector program.">
                <Input type="password" autoComplete="new-password" value={form.password} onChange={e => patch({ password: e.target.value })} />
              </Field>
            )}
          </section>

          <section className="tw:space-y-3">
            <button type="button" onClick={() => setAdvanced(a => !a)} className="tw:flex tw:items-center tw:gap-2 tw:text-xs tw:font-semibold tw:text-muted tw:hover:text-fg">
              {advanced ? <ChevronDown className="tw:size-3.5" /> : <ChevronRight className="tw:size-3.5" />}
              <Settings2 className="tw:size-3.5" />Advanced options
            </button>
            {advanced && (
              <div className="tw:grid tw:grid-cols-1 tw:md:grid-cols-2 tw:gap-3">
                <Field label="Output format">
                  <Select value={form.format} onChange={e => patch({ format: e.target.value as CollectorForm['format'] })}>
                    <option value="jsonl">JSON lines</option><option value="csv">CSV and JSON lines</option>
                  </Select>
                </Field>
                <Field label="Results file name" hint="%Hostname%, %FQDN% and %TIMESTAMP% are filled in.">
                  <Input value={form.filenameTemplate} onChange={e => patch({ filenameTemplate: e.target.value })} />
                </Field>
                <Field label="Collector program name" hint="Empty: a name based on the OS.">
                  <Input value={form.collectorFilename} onChange={e => patch({ collectorFilename: e.target.value })} />
                </Field>
                <Field label="Output folder" hint="Empty: the folder the collector runs from.">
                  <Input value={form.outputDirectory} onChange={e => patch({ outputDirectory: e.target.value })} />
                </Field>
                <Field label="Temp folder"><Input value={form.tempdir} onChange={e => patch({ tempdir: e.target.value })} /></Field>
                <Field label="Compression level (0–9)"><Input inputMode="numeric" value={form.level} onChange={e => patch({ level: e.target.value })} /></Field>
                <Field label="Parallel queries"><Input inputMode="numeric" value={form.concurrency} onChange={e => patch({ concurrency: e.target.value })} /></Field>
                <Field label="CPU limit (%)" hint="0 for no limit."><Input inputMode="numeric" value={form.cpuLimit} onChange={e => patch({ cpuLimit: e.target.value })} /></Field>
                <Field label="Stop when idle for (seconds)"><Input inputMode="numeric" value={form.progressTimeout} onChange={e => patch({ progressTimeout: e.target.value })} /></Field>
                <Field label="Maximum run time (seconds)" hint="0 for no limit."><Input inputMode="numeric" value={form.timeout} onChange={e => patch({ timeout: e.target.value })} /></Field>
                <div className="tw:md:col-span-2">
                  <Switch checked={form.prompt} onChange={v => patch({ prompt: v })} label="Wait for a key press before closing the window" />
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </Dialog>
  );
}

function Heading({ icon, title, hint }: { icon: React.ReactNode; title: string; hint?: string }) {
  return (
    <div className="tw:flex tw:items-center tw:gap-2">
      <span className="tw:text-faint tw:[&>svg]:size-3.5">{icon}</span>
      <h3 className="tw:text-xs tw:font-semibold tw:uppercase tw:tracking-wide tw:text-muted">{title}</h3>
      {hint && <span className="tw:text-2xs tw:text-faint">{hint}</span>}
    </div>
  );
}
