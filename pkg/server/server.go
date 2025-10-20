package server

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
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

// getHeartbeatInterval returns the heartbeat interval from environment variable or default (30s)
func getHeartbeatInterval() time.Duration {
	if envVar := os.Getenv("SLACK_MCP_HEARTBEAT_INTERVAL"); envVar != "" {
		if interval, err := time.ParseDuration(envVar); err == nil {
			return interval
		}
	}
	return 30 * time.Second
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
			mcp.Description("Filter messages in a specific public/private channel by its ID or name. Example: 'C1234567890', 'G1234567890', or '#general'. If not provided, all channels will be searched."),
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

func (s *MCPServer) ServeSSE(addr string) error {
	s.logger.Info("Creating SSE server",
		zap.String("context", "console"),
		zap.String("version", version.Version),
		zap.String("build_time", version.BuildTime),
		zap.String("commit_hash", version.CommitHash),
		zap.String("address", addr),
		zap.String("transport", "SSE"),
	)
	
	// Create SSE server with full configuration
	sseServer := server.NewSSEServer(s.server,
		server.WithBaseURL(fmt.Sprintf("http://%s", addr)),
		server.WithStaticBasePath(""),          // No base path prefix
		server.WithSSEEndpoint("/sse"),         // GET requests for SSE stream
		server.WithMessageEndpoint("/message"), // POST requests for messages
		server.WithKeepAlive(true),
		server.WithKeepAliveInterval(getHeartbeatInterval()), // Keep connections alive
		server.WithSSEContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			// Add auth context for all SSE requests
			ctx = auth.AuthFromRequest(s.logger)(ctx, r)
			return ctx
		}),
	)

	// Create a custom handler that adds auth middleware before SSE server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("Incoming request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("user-agent", r.Header.Get("User-Agent")),
		)
		
		// Health check endpoint (no auth required)
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		
		// All SSE/message requests go through auth middleware then to SSE server
		s.httpAuthMiddleware(sseServer).ServeHTTP(w, r)
	})

	// Create HTTP server with proper timeout configuration for SSE
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,  // Use the custom handler directly
		ReadHeaderTimeout: 30 * time.Second,
		// DO NOT set ReadTimeout or WriteTimeout - they will kill SSE connections!
		// IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	s.logger.Info("SSE server listening", 
		zap.String("address", addr),
		zap.String("sse_endpoint", "/sse"),
		zap.String("message_endpoint", "/message"),
		zap.String("keep_alive_interval", getHeartbeatInterval().String()),
		zap.String("idle_timeout", "120s"),
	)
	
	return httpServer.ListenAndServe()
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
		server.WithStateLess(false),
        server.WithEndpointPath("/mcp"),
        server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
            // Extract auth token and add to context
            ctx = auth.AuthFromRequest(s.logger)(ctx, r)
            return ctx
        }),
        // Enable heartbeat to prevent 60s timeout disconnections
        server.WithHeartbeatInterval(getHeartbeatInterval()),
    )

    // Create HTTP mux with authentication middleware
    mux := http.NewServeMux()
    
    // Add authenticated MCP endpoint
    // Wrap the MCP server with a handler that logs what's happening
	mux.Handle("/mcp", s.httpAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Info("MCP endpoint called",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("content-type", r.Header.Get("Content-Type")),
			zap.String("accept", r.Header.Get("Accept")),
			zap.String("session-id", r.Header.Get("Mcp-Session-Id")),
		)
		
		// Let StreamableHTTPServer handle it
		mcpServer.ServeHTTP(w, r)
		
		s.logger.Info("MCP response sent",
			zap.String("method", r.Method),
			zap.String("response-content-type", w.Header().Get("Content-Type")),
		)
	})))
    
    // Add health check endpoint (no auth required)
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok"}`))
    })

    // Create HTTP server with proper timeout configuration for long-lived SSE connections
    httpServer := &http.Server{
        Addr:              addr,
        Handler:           mux,
        ReadHeaderTimeout: 30 * time.Second,
        // DO NOT set ReadTimeout or WriteTimeout - they will kill SSE streaming connections!
        // The heartbeat mechanism (configured above) keeps connections alive
        IdleTimeout:       120 * time.Second,
        MaxHeaderBytes:    1 << 20, // 1 MB
    }

    // Start server
    s.logger.Info("HTTP server listening", 
        zap.String("address", addr),
        zap.String("heartbeat_interval", getHeartbeatInterval().String()),
        zap.String("idle_timeout", "120s"),
    )
    return httpServer.ListenAndServe()
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

        // Handle CORS preflight
        if r.Method == http.MethodOptions {
            s.logger.Debug("CORS preflight request, skipping auth")
            w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
            w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, HEAD, DELETE")
            w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Session-Id")
            w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
            w.Header().Set("Access-Control-Max-Age", "86400")
            w.WriteHeader(http.StatusNoContent)
            return
        }

        // GET requests are for SSE streams - require authentication
        if r.Method == http.MethodGet {
            s.logger.Debug("GET request for SSE stream",
                zap.String("session_id", r.URL.Query().Get("sessionId")),
            )
            
            // Check authentication for SSE GET requests
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                s.sendHTTP401(w, "missing_authorization",
                    "Missing authorization header for SSE stream",
                    "Include 'Authorization: Bearer <token>' header in your SSE request")
                return
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            if !s.validateToken(token) {
                s.sendHTTP401(w, "invalid_token",
                    "Invalid or expired token for SSE stream",
                    "Check your token validity or refresh your OAuth token")
                return
            }
            
            s.logger.Debug("SSE stream authentication successful", 
                zap.String("session_id", r.URL.Query().Get("sessionId")))
            
            // Add CORS headers
            if origin := r.Header.Get("Origin"); origin != "" {
                w.Header().Set("Access-Control-Allow-Origin", origin)
                w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
            }
            
            // Let the StreamableHTTPServer handle the GET request
            next.ServeHTTP(w, r)
            return
        }

        // POST, HEAD, DELETE - check authentication
        if r.Method == http.MethodPost || r.Method == http.MethodHead || r.Method == http.MethodDelete {
            var mcpMethod string
            if r.Method == http.MethodPost {
                bodyBytes, err := io.ReadAll(r.Body)
                if err == nil {
                    var reqBody map[string]interface{}
                    if json.Unmarshal(bodyBytes, &reqBody) == nil {
                        if method, ok := reqBody["method"].(string); ok {
                            mcpMethod = method
                        }
                    }
                    r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
                }
            }

            s.logger.Debug("Processing MCP request",
                zap.String("http_method", r.Method),
                zap.String("mcp_method", mcpMethod),
            )

            // Skip auth for tools/list (protocol discovery) and ping
            if mcpMethod != "tools/list" && mcpMethod != "ping" {
                authHeader := r.Header.Get("Authorization")
                if authHeader == "" {
                    s.sendHTTP401(w, "missing_authorization",
                        "Missing authorization header",
                        "Include 'Authorization: Bearer <token>' header in your request")
                    return
                }

                token := strings.TrimPrefix(authHeader, "Bearer ")
                if !s.validateToken(token) {
                    s.sendHTTP401(w, "invalid_token",
                        "Invalid or expired token",
                        "Check your token validity or refresh your OAuth token")
                    return
                }
            }
        }

        // Add CORS headers
        if origin := r.Header.Get("Origin"); origin != "" {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
        }

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

// isToolsListRequest checks if the request is for tools/list method
func (s *MCPServer) isToolsListRequest(r *http.Request) bool {
    // Read the body to check the method
    var reqBody map[string]interface{}
    if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
        s.logger.Debug("Failed to decode request body", zap.Error(err))
        return false
    }
    
    // Re-create the body so it can be read again by the handler
    bodyBytes, _ := json.Marshal(reqBody)
    r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
    
    // Check if method is "tools/list"
    method, ok := reqBody["method"].(string)
    if ok && method == "tools/list" {
        s.logger.Debug("Detected tools/list request")
        return true
    }
    
    return false
}

// validateToken validates the OAuth token with Slack API
func (s *MCPServer) validateToken(token string) bool {
    s.logger.Debug("DEBUG: Starting token validation with Slack API", zap.String("token", token))
    
    api := slack.New(token)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    authResp, err := api.AuthTestContext(ctx)
    if err != nil {
        s.logger.Debug("DEBUG: Token validation FAILED", 
            zap.String("token", token),
            zap.Error(err))
        return false
    }
    
    s.logger.Debug("DEBUG: Token validation SUCCESSFUL", 
        zap.String("token", token),
        zap.String("user", authResp.User),
        zap.String("user_id", authResp.UserID),
        zap.String("team", authResp.Team),
        zap.String("team_id", authResp.TeamID))
    
    return true
}