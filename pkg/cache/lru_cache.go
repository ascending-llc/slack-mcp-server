package cache

import (
	"container/list"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Entry represents a cached item with timestamp
type Entry struct {
	key       string
	value     interface{}
	timestamp time.Time
}

// LRUCache is a thread-safe LRU cache with TTL support
type LRUCache struct {
	capacity int
	ttl      time.Duration
	mu       sync.RWMutex
	items    map[string]*list.Element
	evictList *list.List
	logger   *zap.Logger

	// Metrics
	hits   uint64
	misses uint64
	evictions uint64
}

// NewLRUCache creates a new LRU cache with the given capacity and TTL
func NewLRUCache(capacity int, ttl time.Duration, logger *zap.Logger) *LRUCache {
	if capacity <= 0 {
		capacity = 100 // Default capacity
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute // Default TTL
	}

	cache := &LRUCache{
		capacity:  capacity,
		ttl:       ttl,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
		logger:    logger,
	}

	// Start cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, false
	}

	entry := element.Value.(*Entry)

	// Check if expired
	if time.Since(entry.timestamp) > c.ttl {
		c.removeElement(element)
		c.misses++
		c.evictions++
		c.logger.Debug("Cache entry expired",
			zap.String("key_prefix", maskKey(key)),
			zap.Duration("age", time.Since(entry.timestamp)),
		)
		return nil, false
	}

	// Move to front (most recently used)
	c.evictList.MoveToFront(element)
	c.hits++
	
	return entry.value, true
}

// Set adds or updates a value in the cache
func (c *LRUCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if element, ok := c.items[key]; ok {
		c.evictList.MoveToFront(element)
		element.Value.(*Entry).value = value
		element.Value.(*Entry).timestamp = time.Now()
		c.logger.Debug("Cache entry updated",
			zap.String("key_prefix", maskKey(key)),
		)
		return
	}

	// Create new entry
	entry := &Entry{
		key:       key,
		value:     value,
		timestamp: time.Now(),
	}

	// Add to front
	element := c.evictList.PushFront(entry)
	c.items[key] = element

	c.logger.Debug("Cache entry added",
		zap.String("key_prefix", maskKey(key)),
		zap.Int("cache_size", c.evictList.Len()),
	)

	// Evict oldest if over capacity
	if c.evictList.Len() > c.capacity {
		c.evictOldest()
	}
}

// Delete removes a key from the cache
func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.items[key]; ok {
		c.removeElement(element)
		c.logger.Debug("Cache entry deleted",
			zap.String("key_prefix", maskKey(key)),
		)
	}
}

// Clear removes all entries from the cache
func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.evictList.Init()
	c.logger.Info("Cache cleared")
}

// Len returns the current number of items in the cache
func (c *LRUCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.evictList.Len()
}

// Stats returns cache statistics
func (c *LRUCache) Stats() (hits, misses, evictions uint64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, c.evictions, c.evictList.Len()
}

// removeElement removes an element from the cache (must be called with lock held)
func (c *LRUCache) removeElement(element *list.Element) {
	c.evictList.Remove(element)
	entry := element.Value.(*Entry)
	delete(c.items, entry.key)
}

// evictOldest removes the least recently used item (must be called with lock held)
func (c *LRUCache) evictOldest() {
	element := c.evictList.Back()
	if element != nil {
		c.removeElement(element)
		c.evictions++
		c.logger.Debug("Evicted oldest cache entry",
			zap.Int("cache_size", c.evictList.Len()),
			zap.Uint64("total_evictions", c.evictions),
		)
	}
}

// cleanupExpired periodically removes expired entries
func (c *LRUCache) cleanupExpired() {
	ticker := time.NewTicker(c.ttl / 2) // Cleanup at half the TTL interval
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		var toRemove []*list.Element

		// Collect expired entries
		for element := c.evictList.Front(); element != nil; element = element.Next() {
			entry := element.Value.(*Entry)
			if now.Sub(entry.timestamp) > c.ttl {
				toRemove = append(toRemove, element)
			}
		}

		// Remove expired entries
		for _, element := range toRemove {
			c.removeElement(element)
			c.evictions++
		}

		if len(toRemove) > 0 {
			c.logger.Debug("Cleaned up expired cache entries",
				zap.Int("removed", len(toRemove)),
				zap.Int("remaining", c.evictList.Len()),
			)
		}
		c.mu.Unlock()
	}
}

// maskKey returns a prefix of the key for logging (to avoid logging sensitive tokens)
func maskKey(key string) string {
	if len(key) <= 12 {
		return "***"
	}
	return key[:12] + "***"
}
