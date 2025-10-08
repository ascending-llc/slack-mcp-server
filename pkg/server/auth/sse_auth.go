package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/cache"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

var (
	// Global validation cache - initialized on first use
	validationCache *cache.ValidationCache
)

// authKey is a custom context key for storing the auth token.
type authKey struct{}

// withAuthKey adds an auth key to the context.
func withAuthKey(ctx context.Context, auth string) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

// Initialize validation cache lazily
func getValidationCache(logger *zap.Logger) *cache.ValidationCache {
	if validationCache == nil {
		// Get TTL from environment or use default
		ttl := 5 * time.Minute
		if ttlStr := os.Getenv("SLACK_MCP_AUTH_CACHE_TTL"); ttlStr != "" {
			if ttlInt, err := strconv.Atoi(ttlStr); err == nil && ttlInt > 0 {
				ttl = time.Duration(ttlInt) * time.Second
				logger.Info("Using custom auth cache TTL",
					zap.Duration("ttl", ttl))
			}
		}
		validationCache = cache.NewValidationCache(ttl, logger)
		logger.Info("Initialized validation cache",
			zap.Duration("ttl", ttl))
	}
	return validationCache
}

// New OAuth token validation function with caching
func validateOAuthToken(ctx context.Context, logger *zap.Logger) (bool, error) {
	logger.Debug("Context information in OAuth validation")
	token, ok := ctx.Value(authKey{}).(string)

	if !ok || token == "" {
		logger.Warn("Missing OAuth token in context")
		return false, fmt.Errorf("missing OAuth token - please provide Authorization header")
	}

	// Debug: Print the raw token
	logger.Debug("DEBUG: Access token received", zap.String("token", token))

	// Remove Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	
	// Debug: Print the token after removing Bearer prefix
	logger.Debug("DEBUG: Access token after Bearer removal", zap.String("token", token))
	
	// Check if token is empty after removing Bearer prefix
	if token == "" {
		logger.Warn("Empty OAuth token after removing Bearer prefix")
		return false, fmt.Errorf("empty OAuth token - please provide a valid token")
	}

	// Check cache first
	vc := getValidationCache(logger)
	if result, found := vc.Get(token); found {
		if result.Valid {
			logger.Debug("Token validated from cache",
				zap.String("user_id", result.UserID),
				zap.String("team_id", result.TeamID))
			return true, nil
		}
		// Cached invalid result
		return false, fmt.Errorf("token validation failed (cached)")
	}

	// Cache miss - validate with Slack API
	return validateWithSlack(token, logger, vc)
}

// Validate token by calling Slack's auth.test API and cache the result
func validateWithSlack(token string, logger *zap.Logger, vc *cache.ValidationCache) (bool, error) {
	api := slack.New(token)

	// Test the token by calling auth.test
	authTest, err := api.AuthTest()
	if err != nil {
		logger.Warn("Slack API auth.test failed", zap.Error(err))
		
		// Cache the invalid result (with shorter TTL via the cache's default)
		vc.Set(token, &cache.ValidationResult{
			Valid: false,
		})
		
		return false, fmt.Errorf("token validation failed: %v", err)
	}

	// Cache the valid result
	vc.Set(token, &cache.ValidationResult{
		Valid:  true,
		Team:   authTest.Team,
		User:   authTest.User,
		UserID: authTest.UserID,
		TeamID: authTest.TeamID,
	})

	logger.Debug("Token validated with Slack API (cache miss)",
		zap.String("team", authTest.Team),
		zap.String("user", authTest.User),
		zap.String("user_id", authTest.UserID),
		zap.String("team_id", authTest.TeamID))

	return true, nil
}

// AuthFromRequest extracts the auth token from the request headers.
func AuthFromRequest(logger *zap.Logger) func(context.Context, *http.Request) context.Context {
	return func(ctx context.Context, r *http.Request) context.Context {
		authHeader := r.Header.Get("Authorization")
		return withAuthKey(ctx, authHeader)
	}
}

// BuildMiddleware creates a middleware function that ensures authentication based on the provided transport type.
func BuildMiddleware(transport string, logger *zap.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			logger.Debug("Auth middleware invoked",
				zap.String("context", "http"),
				zap.String("transport", transport),
				zap.String("tool", req.Params.Name),
			)

			// Skip auth check for HTTP transport - it's already handled by httpAuthMiddleware
			if transport == "http" {
				logger.Debug("Skipping BuildMiddleware auth for HTTP transport (handled by httpAuthMiddleware)")
				return next(ctx, req)
			}

			if authenticated, err := IsAuthenticated(ctx, transport, logger); !authenticated {
				logger.Error("Authentication failed",
					zap.String("context", "http"),
					zap.String("transport", transport),
					zap.String("tool", req.Params.Name),
					zap.Error(err),
				)
				return nil, err
			}

			logger.Debug("Authentication successful",
				zap.String("context", "http"),
				zap.String("transport", transport),
				zap.String("tool", req.Params.Name),
			)

			return next(ctx, req)
		}
	}
}

// IsAuthenticated public api
func IsAuthenticated(ctx context.Context, transport string, logger *zap.Logger) (bool, error) {
	switch transport {
	case "stdio":
		return true, nil

	case "sse", "http":
		authenticated, err := validateOAuthToken(ctx, logger)

		if err != nil {
			logger.Error("HTTP/SSE authentication error",
				zap.String("context", "http"),
				zap.Error(err),
			)
			return false, fmt.Errorf("authentication error: %w", err)
		}

		if !authenticated {
			logger.Warn("HTTP/SSE unauthorized request",
				zap.String("context", "http"),
			)
			return false, fmt.Errorf("unauthorized request")
		}

		return true, nil

	default:
		logger.Error("Unknown transport type",
			zap.String("context", "http"),
			zap.String("transport", transport),
		)
		return false, fmt.Errorf("unknown transport type: %s", transport)
	}
}

// GetTokenFromContext extracts the token from context (public API)
func GetTokenFromContext(ctx context.Context) (string, bool) {
    token, ok := ctx.Value(authKey{}).(string)
    return token, ok
}
