// Recent response actions: the hunts this page started, with live
// progress. Each row opens the hunt, which lists results per client.
import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { History } from 'lucide-react';
import { useHunts } from '../../lib/queries';
import { toNum, timeAgo } from '../../lib/format';
import { Badge, Card, CardHeader, Skeleton } from '../../ui/primitives';
import { HuntProgress, HuntStateBadge, huntTitle } from '../hunts/HuntBits';
import { RESPONSE_TAG } from './actions';

const MAX_ROWS = 25;

export function ResponseHistory() {
  const { data: hunts = [], isLoading } = useHunts(false);
  const rows = useMemo(() => hunts
    .filter(h => (h.tags ?? []).includes(RESPONSE_TAG))
    .sort((a, b) => toNum(b.create_time) - toNum(a.create_time))
    .slice(0, MAX_ROWS), [hunts]);

  return (
    <Card>
      <CardHeader icon={<History className="tw:size-4" />} title="Recent response actions"
        subtitle="Open one to see the result from each client." />
      <div className="tw:divide-y tw:divide-line">
        {isLoading && <div className="tw:p-4"><Skeleton /></div>}
        {!isLoading && rows.length === 0 && (
          <div className="tw:px-4 tw:py-8 tw:text-center tw:text-xs tw:text-faint">No response actions yet.</div>
        )}
        {rows.map(h => (
          <Link key={h.hunt_id} to={`/hunts/${h.hunt_id}`}
            className="tw:flex tw:flex-wrap tw:items-center tw:gap-x-4 tw:gap-y-1 tw:px-4 tw:py-2.5 tw:hover:bg-hover">
            <div className="tw:min-w-0 tw:flex-1 tw:basis-64">
              <div className="tw:flex tw:items-center tw:gap-2">
                <span className="tw:text-[13px] tw:font-medium tw:truncate">{huntTitle(h)}</span>
                {(h.tags ?? []).includes('dry-run') && <Badge tone="info">Dry run</Badge>}
              </div>
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
