package server

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/korotovsky/slack-mcp-server/pkg/handler"
    "github.com/korotovsky/slack-mcp-server/pkg/provider"
    "github.com/korotovsky/slack-mcp-server/pkg/server/auth"
    "github.com/korotovsky/slack-mcp-server/pkg/text"
    "github.com/korotovsky/slack-mcp-server/pkg/version"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
    "github.com/slack-go/slack"
    "go.uber.org/zap"
)

type MCPServer struct {
	server *server.MCPServer
	logger *zap.Logger
}

func NewMCPServer(provider *provider.TokenBasedApiProvider, logger *zap.Logger) *MCPServer {
	s := server.NewMCPServer(
		"Slack MCP Server",
		version.Version,
		server.WithLogging(),
		server.WithRecovery(),
		server.WithToolHandlerMiddleware(buildLoggerMiddleware(logger)),
		server.WithToolHandlerMiddleware(auth.BuildMiddleware(provider.ServerTransport(), logger)),
	)

	conversationsHandler := handler.NewConversationsHandler(provider, logger)

	s.AddTool(mcp.NewTool("conversations_history",
		mcp.WithDescription("Get messages from the channel (or DM) by channel_id, the last row/column in the response is used as 'cursor' parameter for pagination if not empty"),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("    - `channel_id` (string): ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithBoolean("include_activity_messages",
			mcp.Description("If true, the response will include activity messages such as 'channel_join' or 'channel_leave'. Default is boolean false."),
			mcp.DefaultBool(false),
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithString("limit",
			mcp.DefaultString("1d"),
			mcp.Description("Limit of messages to fetch in format of maximum ranges of time (e.g. 1d - 1 day, 1w - 1 week, 30d - 30 days, 90d - 90 days which is a default limit for free tier history) or number of messages (e.g. 50). Must be empty when 'cursor' is provided."),
		),
	), conversationsHandler.ConversationsHistoryHandler)

	s.AddTool(mcp.NewTool("conversations_replies",
		mcp.WithDescription("Get a thread of messages posted to a conversation by channelID and thread_ts, the last row/column in the response is used as 'cursor' parameter for pagination if not empty"),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithString("thread_ts",
			mcp.Required(),
			mcp.Description("Unique identifier of either a thread's parent message or a message in the thread. ts must be the timestamp in format 1234567890.123456 of an existing message with 0 or more replies."),
		),
		mcp.WithBoolean("include_activity_messages",
			mcp.Description("If true, the response will include activity messages such as 'channel_join' or 'channel_leave'. Default is boolean false."),
			mcp.DefaultBool(false),
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithString("limit",
			mcp.DefaultString("1d"),
			mcp.Description("Limit of messages to fetch in format of maximum ranges of time (e.g. 1d - 1 day, 30d - 30 days, 90d - 90 days which is a default limit for free tier history) or number of messages (e.g. 50). Must be empty when 'cursor' is provided."),
		),
	), conversationsHandler.ConversationsRepliesHandler)

	s.AddTool(mcp.NewTool("conversations_add_message",
		mcp.WithDescription("Add a message to a public channel, private channel, or direct message (DM, or IM) conversation by channel_id and thread_ts."),
		mcp.WithString("channel_id",
			mcp.Required(),
			mcp.Description("ID of the channel in format Cxxxxxxxxxx or its name starting with #... or @... aka #general or @username_dm."),
		),
		mcp.WithString("thread_ts",
			mcp.Description("Unique identifier of either a thread's parent message or a message in the thread_ts must be the timestamp in format 1234567890.123456 of an existing message with 0 or more replies. Optional, if not provided the message will be added to the channel itself, otherwise it will be added to the thread."),
		),
		mcp.WithString("payload",
			mcp.Description("Message payload in specified content_type format. Example: 'Hello, world!' for text/plain or '# Hello, world!' for text/markdown."),
		),
		mcp.WithString("content_type",
			mcp.DefaultString("text/markdown"),
			mcp.Description("Content type of the message. Default is 'text/markdown'. Allowed values: 'text/markdown', 'text/plain'."),
		),
	), conversationsHandler.ConversationsAddMessageHandler)

	s.AddTool(mcp.NewTool("conversations_search_messages",
		mcp.WithDescription("Search messages in a public channel, private channel, or direct message (DM, or IM) conversation using filters. All filters are optional, if not provided then search_query is required."),
		mcp.WithString("search_query",
			mcp.Description("Search query to filter messages. Example: 'marketing report' or full URL of Slack message e.g. 'https://slack.com/archives/C1234567890/p1234567890123456', then the tool will return a single message matching given URL, herewith all other parameters will be ignored."),
		),
		mcp.WithString("filter_in_channel",
			mcp.Description("Filter messages in a specific channel by its ID or name. Example: 'C1234567890' or '#general'. If not provided, all channels will be searched."),
		),
		mcp.WithString("filter_in_im_or_mpim",
			mcp.Description("Filter messages in a direct message (DM) or multi-person direct message (MPIM) conversation by its ID or name. Example: 'D1234567890' or '@username_dm'. If not provided, all DMs and MPIMs will be searched."),
		),
		mcp.WithString("filter_users_with",
			mcp.Description("Filter messages with a specific user by their ID or display name in threads and DMs. Example: 'U1234567890' or '@username'. If not provided, all threads and DMs will be searched."),
		),
		mcp.WithString("filter_users_from",
			mcp.Description("Filter messages from a specific user by their ID or display name. Example: 'U1234567890' or '@username'. If not provided, all users will be searched."),
		),
		mcp.WithString("filter_date_before",
			mcp.Description("Filter messages sent before a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_after",
			mcp.Description("Filter messages sent after a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_on",
			mcp.Description("Filter messages sent on a specific date in format 'YYYY-MM-DD'. Example: '2023-10-01', 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithString("filter_date_during",
			mcp.Description("Filter messages sent during a specific period in format 'YYYY-MM-DD'. Example: 'July', 'Yesterday' or 'Today'. If not provided, all dates will be searched."),
		),
		mcp.WithBoolean("filter_threads_only",
			mcp.Description("If true, the response will include only messages from threads. Default is boolean false."),
		),
		mcp.WithString("cursor",
			mcp.DefaultString(""),
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(20),
			mcp.Description("The maximum number of items to return. Must be an integer between 1 and 100."),
		),
	), conversationsHandler.ConversationsSearchHandler)

	channelsHandler := handler.NewChannelsHandler(provider, logger)

	s.AddTool(mcp.NewTool("channels_list",
		mcp.WithDescription("Get list of channels"),
		mcp.WithString("channel_types",
			mcp.Required(),
			mcp.Description("Comma-separated channel types. Allowed values: 'mpim', 'im', 'public_channel', 'private_channel'. Example: 'public_channel,private_channel,im'"),
		),
		mcp.WithString("sort",
			mcp.Description("Type of sorting. Allowed values: 'popularity' - sort by number of members/participants in each channel."),
		),
		mcp.WithNumber("limit",
			mcp.DefaultNumber(100),
			mcp.Description("The maximum number of items to return. Must be an integer between 1 and 1000 (maximum 999)."), // context fix for cursor: https://github.com/korotovsky/slack-mcp-server/issues/7
		),
		mcp.WithString("cursor",
			mcp.Description("Cursor for pagination. Use the value of the last row and column in the response as next_cursor field returned from the previous request."),
		),
	), channelsHandler.ChannelsHandler)
	
	var ws string
	if provider.Slack() == nil {
		logger.Warn("No static Slack client available, skipping authentication check - OAuth-only mode",
			zap.String("context", "console"),
		)
		ws = os.Getenv("SLACK_WORKSPACE_NAME")
		if ws == "" {
			logger.Fatal("SLACK_WORKSPACE_NAME environment variable is required in OAuth-only mode",
				zap.String("context", "console"),
			)
		}
	}else {
		logger.Info("Authenticating with Slack API...",
			zap.String("context", "console"),
		)
		ar, err := provider.Slack().AuthTest()
		if err != nil {
			logger.Fatal("Failed to authenticate with Slack",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}

		logger.Info("Successfully authenticated with Slack",
			zap.String("context", "console"),
			zap.String("team", ar.Team),
			zap.String("user", ar.User),
			zap.String("enterprise", ar.EnterpriseID),
			zap.String("url", ar.URL),
		)
		ws, err = text.Workspace(ar.URL)
		if err != nil {
			logger.Fatal("Failed to parse workspace from URL",
				zap.String("context", "console"),
				zap.String("url", ar.URL),
				zap.Error(err),
			)
		}

	}

	s.AddResource(mcp.NewResource(
		"slack://"+ws+"/channels",
		"Directory of Slack channels",
		mcp.WithResourceDescription("This resource provides a directory of Slack channels."),
		mcp.WithMIMEType("text/csv"),
	), channelsHandler.ChannelsResource)

	s.AddResource(mcp.NewResource(
		"slack://"+ws+"/users",
		"Directory of Slack users",
		mcp.WithResourceDescription("This resource provides a directory of Slack users."),
		mcp.WithMIMEType("text/csv"),
	), conversationsHandler.UsersResource)

	return &MCPServer{
		server: s,
		logger: logger,
	}
}

func (s *MCPServer) ServeSSE(addr string) *server.SSEServer {
	s.logger.Info("Creating SSE server",
		zap.String("context", "console"),
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
		zap.String("address", addr),
	)
	return server.NewSSEServer(s.server,
		server.WithBaseURL(fmt.Sprintf("http://%s", addr)),
		server.WithSSEContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			ctx = auth.AuthFromRequest(s.logger)(ctx, r)

			return ctx
		}),
	)
}

func (s *MCPServer) ServeHTTP(addr string) error {
	s.logger.Info("Creating HTTP server",
		zap.String("context", "console"),
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
		zap.String("address", addr),
	)
	mcpServer := server.NewStreamableHTTPServer(s.server,
        server.WithEndpointPath("/mcp"),
        server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
            // Extract auth token and add to context
            ctx = auth.AuthFromRequest(s.logger)(ctx, r)
            return ctx
        }),
    )

    // Create HTTP mux with authentication middleware
    mux := http.NewServeMux()
    
    // Add authenticated MCP endpoint
    mux.Handle("/mcp", s.httpAuthMiddleware(mcpServer))
    
    // Add health check endpoint (no auth required)
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    })

    // Start server
    s.logger.Info("HTTP server listening", zap.String("address", addr))
    return http.ListenAndServe(addr, mux)
}

func (s *MCPServer) ServeStdio() error {
	s.logger.Info("Starting STDIO server",
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
	)
	err := server.ServeStdio(s.server)
	if err != nil {
		s.logger.Error("STDIO server error", zap.Error(err))
	}
	return err
}

func buildLoggerMiddleware(logger *zap.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			logger.Info("Request received",
				zap.String("tool", req.Params.Name),
				zap.Any("params", req.Params),
			)

			startTime := time.Now()

			res, err := next(ctx, req)

			duration := time.Since(startTime)

			logger.Info("Request finished",
				zap.String("tool", req.Params.Name),
				zap.Duration("duration", duration),
			)

			return res, err
		}
	}
}

// httpAuthMiddleware wraps an HTTP handler with authentication
func (s *MCPServer) httpAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        s.logger.Debug("HTTP auth middleware",
            zap.String("method", r.Method),
            zap.String("path", r.URL.Path),
        )
		 // Print all headers
        fmt.Printf("Request: %+v\n", r)
		// Handle CORS preflight (OPTIONS) requests - no auth required
        if r.Method == http.MethodOptions {
            s.logger.Debug("CORS preflight request, skipping auth",
                zap.String("origin", r.Header.Get("Origin")),
            )
            w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
            w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, HEAD")
            w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
            w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
            w.WriteHeader(http.StatusNoContent) // 204 No Content
            return
        }

        // Only check authentication for POST and HEAD requests
		if r.Method == http.MethodPost || r.Method == http.MethodHead {
			s.logger.Debug("Checking authentication",
				zap.String("method", r.Method),
			)

			// Check Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				s.sendHTTP401(w, "missing_authorization",
					"Missing authorization header",
					"Include 'Authorization: Bearer <token>' header in your request")
				return
			}


			// Extract and validate token
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if !s.validateToken(token) {
				s.sendHTTP401(w, "invalid_token",
					"Invalid or expired token",
					"Check your token validity or refresh your OAuth token")
				return
			}

			s.logger.Debug("HTTP authentication successful")
		} else {
			s.logger.Debug("Skipping authentication for method",
				zap.String("method", r.Method),
			)
		}

		// Add CORS headers to actual responses
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		// Authentication passed (or not required), continue to MCP handler
		next.ServeHTTP(w, r)
    })
}

// sendHTTP401 sends a 401 Unauthorized response
func (s *MCPServer) sendHTTP401(w http.ResponseWriter, errorType, message, hint string) {
    s.logger.Warn("Sending HTTP 401",
        zap.String("error_type", errorType),
        zap.String("message", message),
    )

    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("WWW-Authenticate", `Bearer realm="Slack MCP Server"`)
    w.WriteHeader(http.StatusUnauthorized)

    response := map[string]interface{}{
        "error":   errorType,
        "message": message,
        "hint":    hint,
        "status":  401,
        "type":    "authentication_required",
    }

    json.NewEncoder(w).Encode(response)
}

// validateToken validates the OAuth token with Slack API
func (s *MCPServer) validateToken(token string) bool {
    api := slack.New(token)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    _, err := api.AuthTestContext(ctx)
    return err == nil
}