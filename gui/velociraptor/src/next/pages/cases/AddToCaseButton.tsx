// "Add to case" for any screen: hunts, collections, hosts, Rapid hunts.
import { useState } from 'react';
import { Briefcase } from 'lucide-react';
import { Button } from '../../ui/primitives';
import { AddToCaseDialog } from './AddToCaseDialog';
import type { NewLink } from './hooks';
import type { CaseSeverity } from './model';

export function AddToCaseButton({ item, suggestedTitle, suggestedSeverity, size, label = 'Add to case' }: {
  item: NewLink; suggestedTitle: string; suggestedSeverity?: CaseSeverity; size?: 'sm' | 'md'; label?: string;
}) {
  const [open, setOpen] = useState(false);
  return <>
    <Button variant="secondary" size={size} icon={<Briefcase className="tw:size-3.5" />} onClick={() => setOpen(true)}>{label}</Button>
    {open && <AddToCaseDialog item={item} suggestedTitle={suggestedTitle} suggestedSeverity={suggestedSeverity}
      onClose={() => setOpen(false)} />}
  </>;
}
