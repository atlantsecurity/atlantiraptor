package ttlcache

import (
	"sync/atomic"
	"time"
)

// touchCounter orders touches that happen within the same clock tick.
// Windows' clock advances in coarse steps (0.5ms to 15.6ms), so items
// added in a burst get identical expireAt values. Without a tie
// breaker the heap evicts an arbitrary one of them, often the newest,
// when the cache is full.
var touchCounter uint64

const (
	// ItemNotExpire Will avoid the item being expired by TTL, but can still be exired by callback etc.
	ItemNotExpire time.Duration = -1
	// ItemExpireWithGlobalTTL will use the global TTL when set.
	ItemExpireWithGlobalTTL time.Duration = 0
)

func newItem(key string, data interface{}, ttl time.Duration) *item {
	item := &item{
		data: data,
		ttl:  ttl,
		key:  key,
	}
	// since nobody is aware yet of this item, it's safe to touch without lock here
	item.touch()
	return item
}

type item struct {
	key        string
	data       interface{}
	ttl        time.Duration
	expireAt   time.Time
	touchSeq   uint64
	queueIndex int
}

// Reset the item expiration time
func (item *item) touch() {
	item.touchSeq = atomic.AddUint64(&touchCounter, 1)
	if item.ttl > 0 {
		item.expireAt = time.Now().Add(item.ttl)
	}
}

// Verify if the item is expired
func (item *item) expired() bool {
	if item.ttl <= 0 {
		return false
	}
	return item.expireAt.Before(time.Now())
}
