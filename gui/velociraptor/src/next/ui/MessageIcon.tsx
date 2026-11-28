// Icon for a console message (see lib/messages): shield for security
// advisories, coloured by severity.
import { Info, Megaphone, ShieldAlert, TriangleAlert, User } from 'lucide-react';
import type { UserMessage } from '../lib/messages';
import { cn } from './primitives';

export function SeverityIcon({ m, className }: { m: Pick<UserMessage, 'severity' | 'category'>; className?: string }) {
  const cls = cn('tw:size-4 tw:shrink-0', className);
  if (m.category === 'security') {
    return <ShieldAlert className={cn(cls, m.severity === 'critical' ? 'tw:text-bad' : 'tw:text-warn')} />;
  }
  if (m.severity === 'critical') return <TriangleAlert className={cn(cls, 'tw:text-bad')} />;
  if (m.severity === 'warning') return <TriangleAlert className={cn(cls, 'tw:text-warn')} />;
  if (m.category === 'message') return <User className={cn(cls, 'tw:text-accent')} />;
  if (m.category === 'announcement') return <Megaphone className={cn(cls, 'tw:text-info')} />;
  return <Info className={cn(cls, 'tw:text-info')} />;
}

