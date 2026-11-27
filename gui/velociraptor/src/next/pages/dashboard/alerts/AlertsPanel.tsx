// Dashboard alerts: what the Sigma and YARA monitors (and any other
// artifact calling alert()) raised in the last 7 days, worst first, with
// drill-down actions on each alert.
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { BellRing, CheckCheck, EyeOff, FlaskConical, Power, X } from 'lucide-react';
import { usePermission, useRecentClients } from '../../../lib/queries';
import { Badge, Button, Card, CardHeader, EmptyState, Segmented, Skeleton, cn } from '../../../ui/primitives';
import { AlertRow } from './AlertRow';
import { bySeverity, sendTestAlert, useAlerts, useAlertTriage, useDetectionSetup } from './hooks';
import { isOpen, removeSuppression, setState, stateOf, suppressedBy, type AlertStatus } from './triage';
import { SEVERITIES, SEVERITY_TONE, type Severity } from './model';

type Filter = 'open24' | 'all';
type View = 'open' | 'all' | 'suppressed';
const DAY_MS = 24 * 3600 * 1000;
const SHOWN = 25;

export function AlertsPanel() {
  const { alerts, isLoading } = useAlerts();
  const triage = useAlertTriage();
  const [view, setView] = useState<View>('open');
  const [filter, setFilter] = useState<Filter>('all');
  const [busy, setBusy] = useState(false);
  const [severity, setSeverity] = useState<Severity | null>(null);
  const [showAll, setShowAll] = useState(false);

  const scoped = useMemo(() => {
    const since = Date.now() - DAY_MS;
    const inRange = filter === 'open24' ? alerts.filter(a => (a.time?.getTime() ?? 0) >= since) : alerts;
    return inRange.filter(a => (view === 'open' ? isOpen(triage.record, a)
      : view === 'suppressed' ? !!suppressedBy(triage.record, a) : true));
  }, [alerts, filter, view, triage.record]);
  const openCount = useMemo(() => alerts.filter(a => isOpen(triage.record, a)).length, [alerts, triage.record]);

  const bulk = async (status: AlertStatus) => {
    setBusy(true);
    try {
      const ids = scoped.map(a => a.id);
      await triage.update(r => setState(r, ids, { status }, triage.me));
      toast.success(`${ids.length} alert${ids.length === 1 ? '' : 's'} marked ${status === 'closed' ? 'closed' : 'acknowledged'}`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    scoped.forEach(a => { c[a.severity] += 1; });
    return c;
  }, [scoped]);
  const visible = useMemo(() => {
    const list = bySeverity(severity ? scoped.filter(a => a.severity === severity) : scoped);
    return showAll ? list : list.slice(0, SHOWN);
  }, [scoped, severity, showAll]);
  const hiddenCount = (severity ? counts[severity] : scoped.length) - visible.length;

  return (
    <Card>
      <CardHeader icon={<BellRing className="tw:size-4" />} title="Alerts"
        subtitle={`${openCount} open · ${filter === 'open24' ? 'raised in the last 24 hours' : 'raised in the last 7 days'}, worst first`}
        actions={<div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5">
          <Segmented value={view} onChange={v => setView(v as View)}
            options={[{ value: 'open', label: 'Open' }, { value: 'all', label: 'All' }, { value: 'suppressed', label: 'Suppressed' }]} />
          <Segmented value={filter} onChange={v => setFilter(v as Filter)}
            options={[{ value: 'open24', label: '24h' }, { value: 'all', label: '7d' }]} />
        </div>} />

      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5 tw:px-4 tw:py-2.5 tw:border-b tw:border-line">
        {SEVERITIES.map(s => (
          <button key={s} type="button" onClick={() => setSeverity(cur => (cur === s ? null : s))}
            className={cn('tw:rounded-md tw:border tw:px-2 tw:py-0.5 tw:text-xs tw:capitalize tw:flex tw:items-center tw:gap-1.5',
              severity === s ? 'tw:border-accent tw:bg-accent-soft' : 'tw:border-line tw:hover:bg-hover',
              counts[s] === 0 && severity !== s && 'tw:opacity-50')}>
            <Badge tone={SEVERITY_TONE[s]} dot>{s}</Badge>
            <span className="rx-num tw:font-semibold">{counts[s]}</span>
          </button>
        ))}
        {view === 'open' && scoped.length > 0 && (
          <span className="tw:flex tw:items-center tw:gap-1">
            <Button size="sm" variant="ghost" icon={<CheckCheck className="tw:size-3.5" />} loading={busy}
              onClick={() => bulk('acknowledged')}>Acknowledge {scoped.length}</Button>
            <Button size="sm" variant="ghost" icon={<X className="tw:size-3.5" />} loading={busy}
              onClick={() => bulk('closed')}>Close {scoped.length}</Button>
          </span>
        )}
        <DetectionControls />
      </div>

      {view === 'suppressed' && triage.record.suppress.length > 0 && (
        <div className="tw:px-4 tw:py-2.5 tw:border-b tw:border-line tw:space-y-1">
          <div className="tw:text-2xs tw:text-muted">Suppression rules (hide matching alerts from Open for everyone):</div>
          {triage.record.suppress.map(sp => (
            <div key={sp.id} className="tw:flex tw:items-center tw:gap-2 tw:text-xs">
              <EyeOff className="tw:size-3.5 tw:text-faint" />
              <span className="tw:font-medium">{sp.rule}</span>
              <span className="tw:text-muted">{sp.clientId ? `on ${sp.clientId}` : 'on every host'} · by {sp.by}</span>
              <button type="button" className="tw:ml-auto tw:text-accent tw:hover:underline"
                onClick={() => triage.update(r => removeSuppression(r, sp.id)).catch(e => toast.error((e as Error).message))}>
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      {isLoading ? (
        <div className="tw:p-4 tw:space-y-3">{[0, 1, 2].map(i => <Skeleton key={i} />)}</div>
      ) : visible.length === 0 ? (
        <EmptyState icon={<BellRing />} title={scoped.length ? 'No alerts at this severity'
          : view === 'open' && alerts.length ? 'Nothing open: every alert has been handled' : 'No alerts'}>
          Alerts appear here when the Sigma and YARA monitors, or any artifact that calls alert(), find something.
        </EmptyState>
      ) : (
        <div className="tw:divide-y tw:divide-line">
          {visible.map(a => <AlertRow key={a.key} alert={a} state={stateOf(triage.record, a)}
            suppressed={!!suppressedBy(triage.record, a)} me={triage.me} update={triage.update} />)}
          {hiddenCount > 0 && (
            <button type="button" onClick={() => setShowAll(true)}
              className="tw:w-full tw:py-2 tw:text-xs tw:text-accent tw:hover:underline">Show {hiddenCount} more</button>
          )}
        </div>
      )}
    </Card>
  );
}

function DetectionControls() {
  const setup = useDetectionSetup();
  const canConfigure = usePermission('collect_client');
  const { data: recent = [] } = useRecentClients(1);
  const [testing, setTesting] = useState(false);
  const target = recent[0];

  const enable = async () => {
    try {
      await setup.enable();
      toast.success('Detections enabled on all clients');
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const test = async () => {
    if (!target?.client_id) return;
    setTesting(true);
    try {
      await sendTestAlert(target.client_id);
      toast.success(`Test alert requested from ${target.os_info?.hostname || target.client_id}. It shows up within a few seconds.`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="tw:ml-auto tw:flex tw:items-center tw:gap-1.5">
      {setup.loaded && (setup.missing.length === 0
        ? <Badge tone="ok" dot>Detections on</Badge>
        : <Button size="sm" variant="primary" icon={<Power className="tw:size-3.5" />} loading={setup.enabling}
            disabled={!canConfigure} onClick={enable}>Enable detections</Button>)}
      <Button size="sm" variant="ghost" icon={<FlaskConical className="tw:size-3.5" />} loading={testing}
        disabled={!target?.client_id || !canConfigure} onClick={test}>Send test alert</Button>
    </div>
  );
}
