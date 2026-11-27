# ttlcache (patched copy)

Copy of `github.com/Velocidex/ttlcache/v2` at
`v2.9.1-0.20240517145123-a3f45e86e130` (MIT licence, see LICENSE), wired in
with a `replace` directive in the top-level `go.mod`.

## Change

When the cache is full, `Set` evicts the item at the root of the expiry
heap. Items were ordered by `expireAt` only. On Windows the clock moves in
coarse steps, so items added in a burst get the same `expireAt` and the heap
evicted an arbitrary one of them, often a newly added item instead of the
oldest one. This made `lru()` in VQL, the ETW process tracker and the
registry and datastore caches drop recent entries.

Each touch now also records a sequence number (`item.touchSeq`), and
`priorityQueue.Less` uses it to break ties, so the least recently used item
is evicted first. `tie_test.go` covers it.
