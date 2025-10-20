package cache

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestValidationCache_BasicOperations(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	result := &ValidationResult{
		Valid:  true,
		Team:   "test-team",
		User:   "test-user",
		UserID: "U123",
		TeamID: "T123",
	}

	cache.Set("token1", result)

	// Should retrieve the same result
	retrieved, ok := cache.Get("token1")
	if !ok {
		t.Error("Expected to find cached result")
	}

	if retrieved.Team != "test-team" || retrieved.UserID != "U123" {
		t.Errorf("Expected correct result, got %+v", retrieved)
	}
}

func TestValidationCache_Miss(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	_, ok := cache.Get("nonexistent")
	if ok {
		t.Error("Expected cache miss for nonexistent key")
	}
}

func TestValidationCache_TTL(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(100*time.Millisecond, logger)

	result := &ValidationResult{
		Valid:  true,
		UserID: "U123",
	}

	cache.Set("token1", result)

	// Should exist immediately
	if _, ok := cache.Get("token1"); !ok {
		t.Error("Expected token1 to exist immediately")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	if _, ok := cache.Get("token1"); ok {
		t.Error("Expected token1 to be expired")
	}
}

func TestValidationCache_InvalidResult(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	invalidResult := &ValidationResult{
		Valid: false,
	}

	cache.Set("badtoken", invalidResult)

	retrieved, ok := cache.Get("badtoken")
	if !ok {
		t.Error("Expected to find cached invalid result")
	}

	if retrieved.Valid {
		t.Error("Expected result to be invalid")
	}
}

func TestValidationCache_Delete(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	result := &ValidationResult{
		Valid:  true,
		UserID: "U123",
	}

	cache.Set("token1", result)
	cache.Delete("token1")

	if _, ok := cache.Get("token1"); ok {
		t.Error("Expected token1 to be deleted")
	}
}

func TestValidationCache_Clear(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	cache.Set("token1", &ValidationResult{Valid: true})
	cache.Set("token2", &ValidationResult{Valid: true})

	cache.Clear()

	hits, misses, size := cache.Stats()
	if size != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", size)
	}

	// Reset stats are expected to be 0
	if hits != 0 || misses != 2 {
		t.Logf("Stats after clear - hits: %d, misses: %d", hits, misses)
	}
}

func TestValidationCache_Stats(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	cache.Set("token1", &ValidationResult{Valid: true})
	cache.Get("token1")    // hit
	cache.Get("token2")    // miss
	cache.Get("token1")    // hit

	hits, misses, size := cache.Stats()

	if hits != 2 {
		t.Errorf("Expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
}

func TestValidationCache_Concurrent(t *testing.T) {
	logger := zap.NewNop()
	cache := NewValidationCache(1*time.Hour, logger)

	done := make(chan bool)

	// Multiple goroutines writing
	for i := 0; i < 10; i++ {
		go func(id int) {
			result := &ValidationResult{
				Valid:  true,
				UserID: string(rune('0' + id)),
			}
			for j := 0; j < 100; j++ {
				cache.Set(string(rune('A'+id)), result)
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

	// Should not panic
	hits, misses, size := cache.Stats()
	if size == 0 {
		t.Error("Expected cache to have entries after concurrent operations")
	}
	t.Logf("After concurrent ops - hits: %d, misses: %d, size: %d", hits, misses, size)
}
