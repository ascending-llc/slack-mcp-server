package cache

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestLRUCache_BasicOperations(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 1*time.Hour, logger)

	// Test Set and Get
	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	cache.Set("key3", "value3")

	if val, ok := cache.Get("key1"); !ok || val != "value1" {
		t.Errorf("Expected to get value1, got %v, ok=%v", val, ok)
	}

	if cache.Len() != 3 {
		t.Errorf("Expected cache length 3, got %d", cache.Len())
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(2, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	cache.Set("key3", "value3") // Should evict key1

	// key1 should be evicted
	if _, ok := cache.Get("key1"); ok {
		t.Error("Expected key1 to be evicted")
	}

	// key2 and key3 should still exist
	if _, ok := cache.Get("key2"); !ok {
		t.Error("Expected key2 to exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}

	if cache.Len() != 2 {
		t.Errorf("Expected cache length 2, got %d", cache.Len())
	}
}

func TestLRUCache_LRUOrder(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(2, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")

	// Access key1, making it more recently used
	cache.Get("key1")

	// Add key3, should evict key2 (least recently used)
	cache.Set("key3", "value3")

	if _, ok := cache.Get("key2"); ok {
		t.Error("Expected key2 to be evicted")
	}
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to still exist")
	}
	if _, ok := cache.Get("key3"); !ok {
		t.Error("Expected key3 to exist")
	}
}

func TestLRUCache_Update(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Set("key1", "value1_updated")

	if val, ok := cache.Get("key1"); !ok || val != "value1_updated" {
		t.Errorf("Expected value1_updated, got %v", val)
	}

	if cache.Len() != 1 {
		t.Errorf("Expected cache length 1, got %d", cache.Len())
	}
}

func TestLRUCache_Delete(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")

	cache.Delete("key1")

	if _, ok := cache.Get("key1"); ok {
		t.Error("Expected key1 to be deleted")
	}
	if cache.Len() != 1 {
		t.Errorf("Expected cache length 1, got %d", cache.Len())
	}
}

func TestLRUCache_Clear(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("Expected cache length 0 after clear, got %d", cache.Len())
	}
}

func TestLRUCache_TTL(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 100*time.Millisecond, logger)

	cache.Set("key1", "value1")

	// Immediately should exist
	if _, ok := cache.Get("key1"); !ok {
		t.Error("Expected key1 to exist immediately")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	if _, ok := cache.Get("key1"); ok {
		t.Error("Expected key1 to be expired")
	}
}

func TestLRUCache_Stats(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(3, 1*time.Hour, logger)

	cache.Set("key1", "value1")
	cache.Get("key1")    // hit
	cache.Get("key2")    // miss
	cache.Get("key1")    // hit

	hits, misses, evictions, size := cache.Stats()

	if hits != 2 {
		t.Errorf("Expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
	if evictions != 0 {
		t.Errorf("Expected 0 evictions, got %d", evictions)
	}
}

func TestLRUCache_Concurrent(t *testing.T) {
	logger := zap.NewNop()
	cache := NewLRUCache(100, 1*time.Hour, logger)

	done := make(chan bool)

	// Multiple goroutines writing
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				cache.Set(string(rune('A'+id)), id)
			}
			done <- true
		}(i)
	}

	// Multiple goroutines reading
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cache.Get("A")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Should not panic and cache should have some entries
	if cache.Len() == 0 {
		t.Error("Expected cache to have entries after concurrent operations")
	}
}
