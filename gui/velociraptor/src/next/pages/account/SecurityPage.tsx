// Account security for the signed-in user: change password and set up
// two-factor sign in with an authenticator app (TOTP) and recovery codes.
import { useState } from 'react';
import { toast } from 'sonner';
import { Copy, KeyRound, ShieldCheck, Smartphone } from 'lucide-react';
import { useSetPassword, useTraits } from '../../lib/queries';
import {
  PASSWORD_RULES, passwordProblems, useMfaActions, useMfaStatus, type TotpBegin,
} from '../../lib/security';
import { Badge, Button, Card, CardHeader, Input, Skeleton } from '../../ui/primitives';

export default function SecurityPage() {
  return (
    <div className="tw:flex-1 tw:overflow-y-auto tw:bg-canvas">
      <div className="tw:p-3 tw:md:p-6 tw:space-y-4">
        <div>
          <h1 className="tw:text-xl tw:font-semibold tw:flex tw:items-center tw:gap-2"><ShieldCheck className="tw:size-5 tw:text-accent" />Account security</h1>
          <p className="tw:text-xs tw:text-muted tw:mt-1">Your password and two-factor sign in.</p>
        </div>
        <div className="tw:grid tw:grid-cols-1 tw:xl:grid-cols-2 tw:gap-4 tw:items-start">
          <TwoFactorCard />
          <PasswordCard />
        </div>
      </div>
    </div>
  );
}

function PasswordCard() {
  const { traits } = useTraits();
  const user = traits?.username ?? '';
  const set = useSetPassword();
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const problems = pw ? passwordProblems(user, pw) : [];
  const mismatch = !!again && pw !== again;

  const save = () => set.mutate({ username: user, password: pw }, {
    onSuccess: () => {
      toast.success('Password changed. Your browser will ask for the new password.');
      setPw('');
      setAgain('');
    },
    onError: e => toast.error((e as Error).message),
  });

  return (
    <Card>
      <CardHeader icon={<KeyRound className="tw:size-4" />} title="Change password"
        subtitle="Changing it also signs out your other two-factor sessions." />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3">
        <Input type="password" autoComplete="new-password" value={pw} onChange={e => setPw(e.target.value)} placeholder="New password" />
        <Input type="password" autoComplete="new-password" value={again} onChange={e => setAgain(e.target.value)} placeholder="Repeat new password" />
        <ul className="tw:text-2xs tw:text-muted tw:list-disc tw:pl-4">
          {PASSWORD_RULES.map(r => <li key={r}>{r}</li>)}
        </ul>
        {problems.length > 0 && <div className="tw:text-2xs tw:text-bad">{problems.join(' ')}</div>}
        {mismatch && <div className="tw:text-2xs tw:text-bad">The two passwords differ.</div>}
        <div className="tw:flex tw:justify-end">
          <Button size="sm" variant="primary" loading={set.isPending} disabled={!pw || problems.length > 0 || pw !== again} onClick={save}>
            Change password
          </Button>
        </div>
      </div>
    </Card>
  );
}

function TwoFactorCard() {
  const status = useMfaStatus();
  const actions = useMfaActions();
  const [setup, setSetup] = useState<TotpBegin | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } catch (e) { toast.error((e as Error).message); } finally { setBusy(false); }
  };

  if (status.isLoading) return <Card><div className="tw:p-4"><Skeleton className="tw:h-24" /></div></Card>;
  const enrolled = !!status.data?.enrolled;

  return (
    <Card>
      <CardHeader icon={<Smartphone className="tw:size-4" />} title="Two-factor sign in"
        subtitle="After your password, enter a code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Yubico Authenticator with a YubiKey)."
        actions={enrolled ? <Badge tone="ok" dot>On</Badge> : <Badge tone="neutral">Off</Badge>} />
      <div className="tw:px-4 tw:pb-4 tw:space-y-3 tw:text-xs">
        {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}

        {!codes && !enrolled && !setup && (
          <Button size="sm" variant="primary" loading={busy} onClick={() => run(async () => setSetup(await actions.begin()))}>
            Set up authenticator app
          </Button>
        )}

        {!codes && !enrolled && setup && (
          <div className="tw:space-y-3">
            <p>1. Scan this code with your authenticator app, or enter the key by hand.</p>
            {setup.qr_png && <img src={setup.qr_png} alt="Authenticator QR code" className="tw:size-48 tw:rounded tw:bg-white tw:p-2" />}
            <div className="tw:font-mono tw:text-[12px] tw:break-all tw:select-all tw:rounded tw:border tw:border-line tw:p-2">{setup.secret}</div>
            <p>2. Enter the 6-digit code it shows.</p>
            <div className="tw:flex tw:gap-2">
              <Input value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" maxLength={6} placeholder="123456" className="tw:font-mono tw:w-32" />
              <Button size="sm" variant="primary" loading={busy} disabled={code.length !== 6}
                onClick={() => run(async () => { setCodes(await actions.confirm(code)); setSetup(null); setCode(''); toast.success('Two-factor sign in is on'); })}>
                Turn on
              </Button>
              <Button size="sm" variant="ghost" onClick={() => { setSetup(null); setCode(''); }}>Cancel</Button>
            </div>
          </div>
        )}

        {!codes && enrolled && (
          <div className="tw:space-y-3">
            <p className="tw:text-muted">{status.data?.recovery_codes_left ?? 0} unused recovery codes left. Enter a current code to change these settings.</p>
            <div className="tw:flex tw:flex-wrap tw:gap-2">
              <Input value={code} onChange={e => setCode(e.target.value)} placeholder="Current code" className="tw:font-mono tw:w-40" />
              <Button size="sm" variant="secondary" loading={busy} disabled={!code}
                onClick={() => run(async () => { setCodes(await actions.regenerate(code)); setCode(''); })}>New recovery codes</Button>
              <Button size="sm" variant="danger" loading={busy} disabled={!code}
                onClick={() => run(async () => { await actions.disable(code); setCode(''); toast.success('Two-factor sign in is off'); })}>Turn off</Button>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <div className="tw:space-y-2 tw:rounded-md tw:border tw:border-warn/40 tw:bg-warn-soft tw:p-3">
      <div className="tw:font-medium">Save these recovery codes now. Each works once if you lose your phone. They will not be shown again.</div>
      <div className="tw:grid tw:grid-cols-2 tw:gap-1 tw:font-mono tw:text-[13px]">{codes.map(c => <span key={c}>{c}</span>)}</div>
      <div className="tw:flex tw:gap-2">
        <Button size="sm" variant="secondary" icon={<Copy className="tw:size-3.5" />}
          onClick={() => navigator.clipboard.writeText(codes.join('\n')).then(() => toast.success('Copied'))}>Copy</Button>
        <Button size="sm" variant="primary" onClick={onDone}>I saved them</Button>
      </div>
    </div>
  );
}
