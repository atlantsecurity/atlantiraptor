// A tool an artifact uses (<velo-tool-viewer name=...> in templates):
// where its binary comes from, so you can check it before collecting.
import { useQuery } from '@tanstack/react-query';
import { Wrench } from 'lucide-react';
import * as api from '../../lib/api';

interface ToolInfo { name?: string; url?: string; filename?: string; hash?: string; version?: string }

export function ToolInfoBadge({ name }: { name: string }) {
  const q = useQuery({
    queryKey: ['tool', name],
    enabled: !!name,
    queryFn: ({ signal }) => api.get<ToolInfo>('v1/GetToolInfo', { name }, signal),
    retry: false,
  });
  const t = q.data;
  return (
    <span className="tw:inline-flex tw:items-center tw:gap-1.5 tw:rounded-md tw:border tw:border-line tw:px-2 tw:py-0.5 tw:text-xs tw:align-middle">
      <Wrench className="tw:size-3 tw:text-faint" />
      <span className="tw:font-mono">{name}</span>
      {q.isLoading ? <span className="tw:text-faint">…</span>
        : q.error ? <span className="tw:text-bad">unknown tool</span>
          : <span className="tw:text-muted tw:break-all">{t?.filename || t?.url || 'not downloaded yet'}{t?.version ? ` · ${t.version}` : ''}</span>}
    </span>
  );
}
