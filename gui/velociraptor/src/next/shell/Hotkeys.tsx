// Global keyboard shortcuts, and the list of them (Ctrl+/).
import { useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Dialog, Kbd } from '../ui/primitives';
import { useSelectedClient } from './client-context';

const SHORTCUTS: { keys: string[]; text: string }[] = [
  { keys: ['Ctrl', 'K'], text: 'Search pages, hosts, hunts and notebooks' },
  { keys: ['Alt', 'D'], text: 'Dashboard' },
  { keys: ['Alt', 'A'], text: 'Artifacts' },
  { keys: ['Alt', 'N'], text: 'Notebooks' },
  { keys: ['Alt', 'C'], text: 'Collections of the selected host' },
  { keys: ['Ctrl', 'Enter'], text: 'Run or save in an editor' },
  { keys: ['Ctrl', '/'], text: 'Show this list (or ?)' },
];

export function Hotkeys() {
  const history = useHistory();
  const { client } = useSelectedClient();
  const [help, setHelp] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement
        && (e.target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName));
      if ((e.ctrlKey && !e.altKey && e.key === '/') || (e.key === '?' && !e.ctrlKey && !e.altKey && !typing)) {
        e.preventDefault();
        setHelp(h => !h);
        return;
      }
      if (!e.altKey || e.ctrlKey || e.metaKey) return;
      const go = (to: string) => { e.preventDefault(); history.push(to); };
      switch (e.code) {
        case 'KeyD': go('/dashboard'); break;
        case 'KeyA': go('/artifacts'); break;
        case 'KeyN': go('/notebooks'); break;
        case 'KeyC': if (client?.client_id) go(`/collected/${client.client_id}`); break;
        default: break;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [history, client?.client_id]);

  return (
    <Dialog open={help} onOpenChange={setHelp} title="Keyboard shortcuts" width={460}>
      <div className="tw:divide-y tw:divide-line">
        {SHORTCUTS.map(s => (
          <div key={s.text} className="tw:flex tw:items-center tw:justify-between tw:gap-4 tw:py-2 tw:text-[13px]">
            <span>{s.text}</span>
            <span className="tw:flex tw:gap-1">{s.keys.map(k => <Kbd key={k}>{k}</Kbd>)}</span>
          </div>
        ))}
      </div>
    </Dialog>
  );
}
