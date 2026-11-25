// Last step before a fleet response action starts. Real (non dry run)
// actions must be confirmed by typing RUN, because they change hosts.
import { useState } from 'react';
import { AlertTriangle, Play } from 'lucide-react';
import { Badge, Button, Dialog, Input, Mono } from '../../ui/primitives';
import type { ResponseAction } from './actions';

const CONFIRM_WORD = 'RUN';

interface ConfirmResponseDialogProps {
  action: ResponseAction;
  params: Record<string, string>;
  targetText: string;
  hostCount: number | undefined;
  dryRun: boolean;
  reason: string;
  needsApproval: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

export function ConfirmResponseDialog({
  action, params, targetText, hostCount, dryRun, reason, needsApproval, onClose, onConfirm,
}: ConfirmResponseDialogProps) {
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const armed = dryRun || typed.trim().toUpperCase() === CONFIRM_WORD;
  const shown = Object.entries(params).filter(([k]) => k !== action.armParam);

  const submit = async () => {
    if (!armed) return;
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={v => !v && onClose()} width={600}
      title={dryRun ? `Dry run: ${action.title}` : `Run ${action.title} on the fleet?`}
      description={dryRun
        ? 'Hosts only report what would change. Nothing is modified.'
        : 'This changes every targeted host as soon as it checks in, and it cannot be undone from here.'}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant={dryRun ? 'primary' : 'danger'} icon={<Play className="tw:size-3.5" />}
          loading={busy} disabled={!armed} onClick={submit}>
          {dryRun ? 'Start dry run' : needsApproval ? 'Send for approval' : `Run on ${hostCount ?? '?'} hosts`}
        </Button>
      </>}>
      <dl className="tw:space-y-2 tw:text-xs">
        <Row label="Action">{action.title}</Row>
        <Row label="Targets">{targetText}</Row>
        <Row label="Hosts now">{hostCount ?? 'estimating…'} <span className="tw:text-faint">(plus any matching host that enrolls while the hunt runs)</span></Row>
        <Row label="Artifacts"><Mono className="tw:text-[11px]">{action.artifacts.join(', ')}</Mono></Row>
        {shown.length > 0 && (
          <Row label="Parameters">
            <div className="tw:space-y-1">
              {shown.map(([k, v]) => (
                <div key={k} className="tw:flex tw:gap-2"><span className="tw:text-muted">{k}</span><Mono className="tw:text-[11px] tw:whitespace-pre-wrap tw:break-all">{v}</Mono></div>
              ))}
            </div>
          </Row>
        )}
        <Row label="Mode">
          {dryRun ? <Badge tone="info">Dry run</Badge> : <Badge tone="bad">Live</Badge>}
          {needsApproval && <span className="tw:ml-2 tw:text-muted">Starts paused until another user approves it.</span>}
        </Row>
        {reason && <Row label="Reason"><span className="tw:whitespace-pre-wrap">{reason}</span></Row>}
      </dl>
      {!dryRun && (
        <div className="tw:mt-4 tw:rounded-md tw:border tw:border-bad/40 tw:bg-bad-soft tw:p-3">
          <div className="tw:flex tw:items-center tw:gap-2 tw:text-xs tw:font-medium tw:text-bad">
            <AlertTriangle className="tw:size-3.5" /> Type {CONFIRM_WORD} to confirm
          </div>
          <Input autoFocus value={typed} onChange={e => setTyped(e.target.value)} className="tw:mt-2 tw:font-mono"
            onKeyDown={e => { if (e.key === 'Enter') submit(); }} />
        </div>
      )}
    </Dialog>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="tw:grid tw:grid-cols-[90px_1fr] tw:gap-3">
      <dt className="tw:text-muted">{label}</dt>
      <dd className="tw:min-w-0">{children}</dd>
    </div>
  );
}
