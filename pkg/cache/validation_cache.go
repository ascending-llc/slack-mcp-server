package cache

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// ValidationResult represents a cached validation result
type ValidationResult struct {
	Valid     bool
	Team      string
	User      string
	UserID    string
	TeamID    string
	ExpiresAt time.Time
}

// ValidationCache caches token validation results to reduce API calls
type ValidationCache struct {
	cache  map[string]*ValidationResult
	mu     sync.RWMutex
	ttl    time.Duration
	logger *zap.Logger

	// Metrics
	hits   uint64
	misses uint64
}

// NewValidationCache creates a new validation cache with the given TTL
func NewValidationCache(ttl time.Duration, logger *zap.Logger) *ValidationCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default TTL for validation
	}

	vc := &ValidationCache{
		cache:  make(map[string]*ValidationResult),
		ttl:    ttl,
		logger: logger,
	}

	// Start cleanup goroutine
	go vc.cleanupExpired()

	return vc
}

// Get retrieves a validation result from the cache
func (vc *ValidationCache) Get(token string) (*ValidationResult, bool) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	result, ok := vc.cache[token]
	if !ok {
		vc.misses++
		return nil, false
	}

	// Check if expired
	if time.Now().After(result.ExpiresAt) {
		vc.misses++
		return nil, false
	}

	vc.hits++
	vc.logger.Debug("Validation cache hit",
		zap.String("user_id", result.UserID),
		zap.String("team_id", result.TeamID),
	)
	
	return result, true
}

// Set adds or updates a validation result in the cache
func (vc *ValidationCache) Set(token string, result *ValidationResult) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	result.ExpiresAt = time.Now().Add(vc.ttl)
	vc.cache[token] = result

	vc.logger.Debug("Validation result cached",
		zap.String("user_id", result.UserID),
		zap.String("team_id", result.TeamID),
		zap.Duration("ttl", vc.ttl),
	)
}

// Delete removes a token from the validation cache
func (vc *ValidationCache) Delete(token string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	delete(vc.cache, token)
	vc.logger.Debug("Validation cache entry deleted")
}

// Clear removes all entries from the cache
func (vc *ValidationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.cache = make(map[string]*ValidationResult)
	vc.logger.Info("Validation cache cleared")
}

// Stats returns cache statistics
func (vc *ValidationCache) Stats() (hits, misses uint64, size int) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.hits, vc.misses, len(vc.cache)
}

// cleanupExpired periodically removes expired entries
func (vc *ValidationCache) cleanupExpired() {
	ticker := time.NewTicker(vc.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		vc.mu.Lock()
		now := time.Now()
		var toRemove []string

		// Collect expired entries
		for token, result := range vc.cache {
			if now.After(result.ExpiresAt) {
				toRemove = append(toRemove, token)
			}
		}

		// Remove expired entries
		for _, token := range toRemove {
			delete(vc.cache, token)
		}

		if len(toRemove) > 0 {
			vc.logger.Debug("Cleaned up expired validation cache entries",
				zap.Int("removed", len(toRemove)),
				zap.Int("remaining", len(vc.cache)),
			)
		}
		vc.mu.Unlock()
	}
}
