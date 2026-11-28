// The signed-in user's own settings, and the help dialog (documentation
// and shortcuts), both opened from the top bar.
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { BookOpen, ExternalLink, Keyboard, LifeBuoy, ShieldCheck } from 'lucide-react';
import * as api from '../lib/api';
import { useTraits } from '../lib/queries';
import { Button, Dialog, Field, Input, Segmented, Select } from '../ui/primitives';
import { isDarkTheme, setTheme } from './theme';

const DOCS = 'https://atlantsecurity.github.io/atlantiraptor/';

function timezones(): string[] {
  try {
    return (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf('timeZone');
  } catch {
    return ['UTC'];
  }
}

export function UserSettingsDialog({ onClose }: { onClose: () => void }) {
  const { traits, updateTraits } = useTraits();
  const zones = useMemo(() => ['UTC', ...timezones().filter(z => z !== 'UTC')], []);
  const [timezone, setTimezone] = useState(traits?.timezone || 'UTC');
  const [downloadPassword, setDownloadPassword] = useState(traits?.default_password || '');
  const [dark, setDark] = useState(isDarkTheme(traits?.theme));
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      const params: Record<string, unknown> = {};
      if (timezone !== (traits?.timezone || 'UTC')) params.timezone = timezone;
      // "-" clears the stored password (an empty value means "unchanged").
      if (downloadPassword !== (traits?.default_password || '')) params.default_password = downloadPassword || '-';
      if (Object.keys(params).length) await api.post('v1/SetGUIOptions', params);
      if (dark !== isDarkTheme(traits?.theme)) await setTheme(dark, traits?.ui_settings, () => undefined);
      updateTraits();
      toast.success('Settings saved');
      onClose();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={v => !v && onClose()} title="Your settings" description={traits?.username} width={520}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={busy} onClick={save}>Save</Button>
      </>}>
      <div className="tw:space-y-4">
        <Field label="Theme">
          <Segmented size="md" value={dark ? 'dark' : 'light'} onChange={v => setDark(v === 'dark')}
            options={[{ value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]} />
        </Field>
        <Field label="Time zone" hint="Times in the console are shown in this zone.">
          <Select value={timezone} onChange={e => setTimezone(e.target.value)}>
            {zones.map(z => <option key={z} value={z}>{z}</option>)}
          </Select>
        </Field>
        <Field label="Password for downloads" hint="Zip exports you download are protected with this password. Leave empty for none.">
          <Input type="password" autoComplete="new-password" value={downloadPassword} onChange={e => setDownloadPassword(e.target.value)} />
        </Field>
        <div className="tw:flex tw:items-center tw:gap-2 tw:border-t tw:border-line tw:pt-3 tw:text-xs tw:text-muted">
          <ShieldCheck className="tw:size-3.5" />
          <span>Password and two-step sign-in are under <a href="#/account/security" onClick={onClose} className="tw:text-accent">Account security</a>.</span>
        </div>
      </div>
    </Dialog>
  );
}

export function HelpDialog({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState('');
  const links = [
    { icon: <BookOpen />, title: 'Documentation', text: 'Guides from first steps to deployment.', url: DOCS },
    { icon: <LifeBuoy />, title: 'Quick start', text: 'Run a first hunt in ten minutes.', url: `${DOCS}quickstart/` },
    { icon: <BookOpen />, title: 'VQL reference', text: 'Every plugin and function.', url: `${DOCS}vql/` },
    { icon: <LifeBuoy />, title: 'Support', text: 'Contact Atlant Security.', url: `${DOCS}support/` },
  ];
  return (
    <Dialog open onOpenChange={v => !v && onClose()} title="Help" width={560}>
      <div className="tw:space-y-4">
        <form className="tw:flex tw:gap-2" onSubmit={e => {
          e.preventDefault();
          if (q.trim()) window.open(`${DOCS}?q=${encodeURIComponent(q.trim())}`, '_blank', 'noopener');
        }}>
          <Input value={q} onChange={e => setQ(e.target.value)} placeholder="Search the documentation" className="tw:flex-1" />
          <Button type="submit" variant="secondary" disabled={!q.trim()}>Search</Button>
        </form>
        <div className="tw:grid tw:grid-cols-1 tw:sm:grid-cols-2 tw:gap-2">
          {links.map(l => (
            <a key={l.title} href={l.url} target="_blank" rel="noreferrer"
              className="tw:flex tw:items-start tw:gap-3 tw:rounded-lg tw:border tw:border-line tw:p-3 tw:text-fg tw:no-underline tw:hover:border-accent tw:hover:bg-hover">
              <span className="tw:text-accent tw:[&>svg]:size-4 tw:mt-0.5">{l.icon}</span>
              <span className="tw:min-w-0">
                <span className="tw:flex tw:items-center tw:gap-1 tw:text-[13px] tw:font-medium">{l.title}<ExternalLink className="tw:size-3 tw:text-faint" /></span>
                <span className="tw:block tw:text-2xs tw:text-muted">{l.text}</span>
              </span>
            </a>
          ))}
        </div>
        <div className="tw:flex tw:items-center tw:gap-2 tw:text-xs tw:text-muted">
          <Keyboard className="tw:size-3.5" />Press Ctrl+/ for keyboard shortcuts.
        </div>
      </div>
    </Dialog>
  );
}
