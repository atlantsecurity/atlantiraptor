// IOC sweep: paste indicators, check what was understood, pick targets
// and hunt the fleet for all of them in one go.
import { useMemo, useState } from 'react';
import { Link, useHistory } from 'react-router-dom';
import { toast } from 'sonner';
import { Play, ScanSearch } from 'lucide-react';
import { useCreateHunt, useEstimateHunt, useRecentHunts, usePermission } from '../../lib/queries';
import type { HuntCondition } from '../../lib/types';
import { timeAgo, toNum } from '../../lib/format';
import { Badge, Button, Card, CardHeader, Input, Select, Switch, Textarea, cn } from '../../ui/primitives';
import { TagInput } from '../hunts/TagInput';
import { untilStoppedExpiry } from '../hunts/time';
import { HuntProgress, HuntStateBadge, huntTitle } from '../hunts/HuntBits';
import { IOC_TYPES, parseIocs, toCsv, type IocType } from './parse';

export const IOC_ARTIFACT = 'Generic.Detection.IOCSweep';
export const IOC_TAG = 'ioc-sweep';
import { IOC_PREFILL_KEY } from '../../lib/prefill';
export { IOC_PREFILL_KEY };
const DEFAULT_GLOB = 'C:/Users/*/{Downloads,Desktop,Documents,AppData/Local/Temp,AppData/Roaming}/**';
const PLACEHOLDER = `One indicator per line, or type,value,note. Defanged values are fine.
e.g.
44d88612fea8a8f36de82e1278abb02f
evil-c2[.]example
hxxps://bad.example/payload
185.220.101.4
C:\\ProgramData\\updater\\svc.exe
invoice_2024.js`;

type Mode = 'labels' | 'os' | 'all';

function takePrefill(): string {
  try {
    const v = sessionStorage.getItem(IOC_PREFILL_KEY) ?? '';
    sessionStorage.removeItem(IOC_PREFILL_KEY);
    return v;
  } catch {
    return '';
  }
}

export default function IocSweepPage() {
  const history = useHistory();
  const create = useCreateHunt();
  const canHunt = usePermission('start_hunt');
  const [text, setText] = useState(takePrefill);
  const [mode, setMode] = useState<Mode>('all');
  const [labels, setLabels] = useState<string[]>([]);
  const [os, setOs] = useState('WINDOWS');
  const [glob, setGlob] = useState(DEFAULT_GLOB);
  const [alerts, setAlerts] = useState(true);
  const [busy, setBusy] = useState(false);
  const [untilStopped, setUntilStopped] = useState(false);

  const parsed = useMemo(() => parseIocs(text), [text]);
  const counts = useMemo(() => {
    const c = Object.fromEntries(IOC_TYPES.map(t => [t, 0])) as Record<IocType, number>;
    parsed.iocs.forEach(i => { c[i.type] += 1; });
    return c;
  }, [parsed]);
  const condition: HuntCondition = useMemo(() => (
    mode === 'labels' && labels.length ? { labels: { label: labels } } : mode === 'os' ? { os: { os } } : {}), [mode, labels, os]);
  const missingLabels = mode === 'labels' && labels.length === 0;
  const estimate = useEstimateHunt(condition, 'all', !missingLabels);

  const start = async () => {
    setBusy(true);
    try {
      const env = [
        { key: 'IOCs', value: toCsv(parsed.iocs) },
        { key: 'HashGlob', value: glob },
        { key: 'RaiseAlerts', value: alerts ? 'Y' : 'N' },
      ];
      const r = await create.mutateAsync({
        hunt_description: `IOC sweep: ${parsed.iocs.length} indicators`,
        tags: [IOC_TAG],
        start_request: { artifacts: [IOC_ARTIFACT], specs: [{ artifact: IOC_ARTIFACT, parameters: { env } }] },
        condition,
        state: 2,
        ...(untilStopped ? { expires: untilStoppedExpiry() } : {}),
      });
      toast.success('IOC sweep started');
      if (r.flow_id) history.push(`/hunts/${r.flow_id}`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><ScanSearch className="tw:size-5 tw:text-accent" />IOC sweep</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">Check the fleet for file hashes, IPs, domains, paths and file names in one hunt. Hits also appear as dashboard alerts.</p>
        </div>

        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-[1fr_380px] tw:gap-4 tw:items-start">
          <Card>
            <CardHeader title="Indicators" subtitle={`${parsed.iocs.length} recognised${parsed.rejected.length ? `, ${parsed.rejected.length} not recognised` : ''}`} />
            <div className="tw:px-4 tw:pb-4 tw:space-y-3">
              <Textarea rows={12} value={text} onChange={e => setText(e.target.value)} placeholder={PLACEHOLDER} className="tw:font-mono tw:text-xs" />
              <div className="tw:flex tw:flex-wrap tw:gap-1.5">
                {IOC_TYPES.map(t => <Badge key={t} tone={counts[t] ? 'accent' : 'neutral'}>{t} {counts[t]}</Badge>)}
              </div>
              {parsed.rejected.length > 0 && (
                <div className="tw:text-2xs tw:text-warn">
                  Not recognised (use type,value to force a type): <span className="tw:font-mono">{parsed.rejected.slice(0, 8).join(' · ')}{parsed.rejected.length > 8 ? ' …' : ''}</span>
                </div>
              )}
            </div>
          </Card>

          <Card>
            <CardHeader title="Sweep" />
            <div className="tw:px-4 tw:pb-4 tw:space-y-3">
              <div className="tw:flex tw:flex-wrap tw:gap-1.5">
                {(['all', 'labels', 'os'] as Mode[]).map(m => (
                  <button key={m} type="button" onClick={() => setMode(m)}
                    className={cn('tw:rounded-md tw:border tw:px-2.5 tw:py-1 tw:text-xs',
                      mode === m ? 'tw:border-accent tw:bg-accent-soft tw:text-accent tw:font-medium' : 'tw:border-line tw:hover:bg-hover')}>
                    {m === 'all' ? 'All clients' : m === 'labels' ? 'By label' : 'By OS'}
                  </button>
                ))}
              </div>
              {mode === 'labels' && <TagInput value={labels} onChange={setLabels} tone="accent" placeholder="Labels" />}
              {mode === 'os' && (
                <Select value={os} onChange={e => setOs(e.target.value)}>
                  <option value="WINDOWS">Windows</option><option value="LINUX">Linux</option><option value="OSX">macOS</option>
                </Select>
              )}
              <div className="tw:text-xs tw:text-muted">{missingLabels ? 'Add at least one label.' : <>Matches <b className="tw:text-fg">{estimate.data ?? '…'}</b> clients now.</>}</div>
              <label className="tw:block">
                <span className="tw:block tw:text-xs tw:font-medium tw:mb-1.5">Where to look for hashes and file names</span>
                <Input value={glob} onChange={e => setGlob(e.target.value)} className="tw:font-mono tw:text-xs" />
              </label>
              <Switch checked={alerts} onChange={setAlerts} label="Raise a dashboard alert for each hit" />
              <Switch checked={untilStopped} onChange={setUntilStopped} label="Run until stopped (otherwise it stops after 1 hour)" />
              <Button variant="primary" className="tw:w-full" icon={<Play className="tw:size-3.5" />} loading={busy}
                disabled={!canHunt || parsed.iocs.length === 0 || missingLabels} onClick={start}>
                Sweep for {parsed.iocs.length} indicators
              </Button>
            </div>
          </Card>
        </div>

        <RecentSweeps />
      </div>
    </div>
  );
}

function RecentSweeps() {
  const { data: hunts = [] } = useRecentHunts();
  const rows = useMemo(() => hunts.filter(h => (h.tags ?? []).includes(IOC_TAG))
    .sort((a, b) => toNum(b.create_time) - toNum(a.create_time)).slice(0, 15), [hunts]);
  return (
    <Card>
      <CardHeader title="Recent sweeps" subtitle="Open a sweep to see hits per client" />
      <div className="tw:divide-y tw:divide-line">
        {rows.length === 0 && <div className="tw:px-4 tw:py-6 tw:text-center tw:text-xs tw:text-faint">No sweeps yet.</div>}
        {rows.map(h => (
          <Link key={h.hunt_id} to={`/hunts/${h.hunt_id}`} className="tw:flex tw:flex-wrap tw:items-center tw:gap-x-4 tw:gap-y-1 tw:px-4 tw:py-2.5 tw:hover:bg-hover">
            <div className="tw:min-w-0 tw:flex-1 tw:basis-64">
              <div className="tw:text-[13px] tw:font-medium tw:truncate">{huntTitle(h)}</div>
              <div className="tw:text-2xs tw:text-faint">{h.hunt_id} · {timeAgo(h.create_time)} · {h.creator}</div>
            </div>
            <HuntStateBadge hunt={h} />
            <HuntProgress hunt={h} className="tw:w-48" />
          </Link>
        ))}
      </div>
    </Card>
  );
}
