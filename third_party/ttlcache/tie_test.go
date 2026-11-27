package ttlcache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// On Windows many items added in a burst share one expiry time. Pin
// every expiry to the same instant and check that the size limit still
// evicts the oldest items, not arbitrary ones.
func TestSizeEvictionWithEqualExpiry(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	assert.NoError(t, cache.SetTTL(time.Hour))
	cache.SetCacheSizeLimit(3)

	same := time.Now().Add(time.Hour)
	for _, key := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"} {
		assert.NoError(t, cache.Set(key, key))

		// Give every item the same expiry, as a coarse clock would.
		cache.mutex.Lock()
		for _, it := range cache.items {
			it.expireAt = same
		}
		cache.mutex.Unlock()
	}

	keys := cache.GetKeys()
	assert.ElementsMatch(t, []string{"7", "8", "9"}, keys)
}
