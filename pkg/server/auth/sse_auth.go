package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

// authKey is a custom context key for storing the auth token.
type authKey struct{}

// withAuthKey adds an auth key to the context.
func withAuthKey(ctx context.Context, auth string) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

// Authenticate checks if the request is authenticated based on the provided context.

// New OAuth token validation function
func validateOAuthToken(ctx context.Context, logger *zap.Logger) (bool, error) {
     // Debug: Print context information
    logger.Debug("Context information in OAuth validation")
	fmt.Printf("Context: %+v\n", ctx)
    token, ok := ctx.Value(authKey{}).(string)

	fmt.Printf("Extracted token: %s, ok: %v\n", token, ok)

    if !ok {
        logger.Warn("Missing OAuth token in context")
        return false, fmt.Errorf("missing OAuth token")
    }

    // Remove Bearer prefix if present
    if strings.HasPrefix(token, "Bearer ") {
        token = strings.TrimPrefix(token, "Bearer ")
    }

    // Validate token with Slack API instead of local comparison
    return validateWithSlack(token, logger)
}

// Validate token by calling Slack's auth.test API
func validateWithSlack(token string, logger *zap.Logger) (bool, error) {
    api := slack.New(token)
    
    // Test the token by calling auth.test
    authTest, err := api.AuthTest()
    if err != nil {
        logger.Warn("Slack API auth.test failed", zap.Error(err))
        return false, fmt.Errorf("token validation failed: %v", err)
    }

    // If we get here, the token is valid (no error from AuthTest)
    logger.Debug("Token validated with Slack API",
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
