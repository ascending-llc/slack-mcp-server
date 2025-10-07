package provider

import (
	"context"
	// "encoding/json"
	"errors"
	"fmt"
	// "io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/korotovsky/slack-mcp-server/pkg/limiter"
	"github.com/korotovsky/slack-mcp-server/pkg/provider/edge"
	"github.com/korotovsky/slack-mcp-server/pkg/transport"
	localauth "github.com/korotovsky/slack-mcp-server/pkg/server/auth"
	"github.com/rusq/slackdump/v3/auth"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const usersNotReadyMsg = "users cache is not ready yet, sync process is still running... please wait"
const channelsNotReadyMsg = "channels cache is not ready yet, sync process is still running... please wait"
const defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"

var AllChanTypes = []string{"mpim", "im", "public_channel", "private_channel"}
var PrivateChanType = "private_channel"
var PubChanType = "public_channel"

var ErrUsersNotReady = errors.New(usersNotReadyMsg)
var ErrChannelsNotReady = errors.New(channelsNotReadyMsg)

type UsersCache struct {
	Users    map[string]slack.User `json:"users"`
	UsersInv map[string]string     `json:"users_inv"`
}

type ChannelsCache struct {
	Channels    map[string]Channel `json:"channels"`
	ChannelsInv map[string]string  `json:"channels_inv"`
}

type Channel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Topic       string `json:"topic"`
	Purpose     string `json:"purpose"`
	MemberCount int    `json:"memberCount"`
	IsMpIM      bool   `json:"mpim"`
	IsIM        bool   `json:"im"`
	IsPrivate   bool   `json:"private"`
}

type SlackAPI interface {
	// Standard slack-go API methods
	AuthTest() (*slack.AuthTestResponse, error)
	AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error)
	GetUsersContext(ctx context.Context, options ...slack.GetUsersOption) ([]slack.User, error)
	GetUsersInfo(users ...string) (*[]slack.User, error)
	PostMessageContext(ctx context.Context, channel string, options ...slack.MsgOption) (string, string, error)
	MarkConversationContext(ctx context.Context, channel, ts string) error

	// Used to get messages
	GetConversationHistoryContext(ctx context.Context, params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error)
	GetConversationRepliesContext(ctx context.Context, params *slack.GetConversationRepliesParameters) (msgs []slack.Message, hasMore bool, nextCursor string, err error)
	SearchContext(ctx context.Context, query string, params slack.SearchParameters) (*slack.SearchMessages, *slack.SearchFiles, error)

	// Used to get channels list from both Slack and Enterprise Grid versions
	GetConversationsContext(ctx context.Context, params *slack.GetConversationsParameters) ([]slack.Channel, string, error)

	// Edge API methods
	ClientUserBoot(ctx context.Context) (*edge.ClientUserBootResponse, error)
}

type MCPSlackClient struct {
	slackClient *slack.Client
	edgeClient  *edge.Client

	authResponse *slack.AuthTestResponse
	authProvider auth.Provider

	isEnterprise bool
	isOAuth      bool
	teamEndpoint string
}

type ApiProvider struct {
	transport string
	client    SlackAPI
	logger    *zap.Logger

	rateLimiter *rate.Limiter

	users      map[string]slack.User
	usersInv   map[string]string
	// usersCache string
	usersReady bool

	channels      map[string]Channel
	channelsInv   map[string]string
	// channelsCache string
	channelsReady bool
}

// TokenBasedApiProvider supports creating clients from tokens dynamically
type TokenBasedApiProvider struct {
	*ApiProvider
}

// CreateClientFromToken creates a new Slack client from an OAuth token
func (tap *TokenBasedApiProvider) CreateClientFromToken(oauthToken string) (SlackAPI, error) {
	return NewMCPSlackClientFromToken(oauthToken, tap.logger)
}

// GetClientFromContext extracts token from context and creates/returns appropriate client
func (tap *TokenBasedApiProvider) GetClientFromContext(ctx context.Context) (SlackAPI, error) {
	// Check if we have a static client (from environment variables)
	if tap.client != nil {
		return tap.client, nil
	}

	 // Debug: Print context information
    tap.logger.Debug("Context information in CLIENT validation")
	fmt.Printf("Context: %+v\n", ctx)

	// Extract token from context (set by AuthFromRequest)
	token, ok := localauth.GetTokenFromContext(ctx)

	fmt.Printf("Extracted token: %s, ok: %v\n", token, ok)

	if !ok {
		return nil, fmt.Errorf("no authentication token found in context")
	}

	// Remove Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Create client from token
	return tap.CreateClientFromToken(token)
}

func NewMCPSlackClient(authProvider auth.Provider, logger *zap.Logger) (*MCPSlackClient, error) {
	httpClient := transport.ProvideHTTPClient(authProvider.Cookies(), logger)

	slackClient := slack.New(authProvider.SlackToken(),
		slack.OptionHTTPClient(httpClient),
	)

	authResp, err := slackClient.AuthTest()
	if err != nil {
		return nil, err
	}

	return createMCPSlackClient(slackClient, authResp, authProvider, httpClient, logger)
}

// NewMCPSlackClientFromToken creates a new MCP Slack client from an OAuth token
func NewMCPSlackClientFromToken(oauthToken string, logger *zap.Logger) (*MCPSlackClient, error) {
	// Create auth provider from token
	authProvider, err := auth.NewValueAuth(oauthToken, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create auth provider: %w", err)
	}

	httpClient := transport.ProvideHTTPClient(authProvider.Cookies(), logger)

	slackClient := slack.New(oauthToken, slack.OptionHTTPClient(httpClient))

	authResp, err := slackClient.AuthTest()
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return createMCPSlackClient(slackClient, authResp, authProvider, httpClient, logger)
}

// createMCPSlackClient is a helper function to create MCPSlackClient from components
func createMCPSlackClient(slackClient *slack.Client, authResp *slack.AuthTestResponse, authProvider auth.Provider, httpClient *http.Client, logger *zap.Logger) (*MCPSlackClient, error) {
	authResponse := &slack.AuthTestResponse{
		URL:          authResp.URL,
		Team:         authResp.Team,
		User:         authResp.User,
		TeamID:       authResp.TeamID,
		UserID:       authResp.UserID,
		EnterpriseID: authResp.EnterpriseID,
		BotID:        authResp.BotID,
	}

	slackClient = slack.New(authProvider.SlackToken(),
		slack.OptionHTTPClient(httpClient),
		slack.OptionAPIURL(authResp.URL+"api/"),
	)

	edgeClient, err := edge.NewWithInfo(authResponse, authProvider,
		edge.OptionHTTPClient(httpClient),
	)
	if err != nil {
		return nil, err
	}

	isEnterprise := authResp.EnterpriseID != ""

	return &MCPSlackClient{
		slackClient:  slackClient,
		edgeClient:   edgeClient,
		authResponse: authResponse,
		authProvider: authProvider,
		isEnterprise: isEnterprise,
		isOAuth:      true, // Always OAuth since we only support OAuth tokens now
		teamEndpoint: authResp.URL,
	}, nil
}

func (c *MCPSlackClient) AuthTest() (*slack.AuthTestResponse, error) {
	if c.authResponse != nil {
		return c.authResponse, nil
	}

	return c.slackClient.AuthTest()
}

func (c *MCPSlackClient) AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error) {
	return c.slackClient.AuthTestContext(ctx)
}

func (c *MCPSlackClient) GetUsersContext(ctx context.Context, options ...slack.GetUsersOption) ([]slack.User, error) {
	return c.slackClient.GetUsersContext(ctx, options...)
}

func (c *MCPSlackClient) GetUsersInfo(users ...string) (*[]slack.User, error) {
	return c.slackClient.GetUsersInfo(users...)
}

func (c *MCPSlackClient) MarkConversationContext(ctx context.Context, channel, ts string) error {
	return c.slackClient.MarkConversationContext(ctx, channel, ts)
}

func (c *MCPSlackClient) GetConversationsContext(ctx context.Context, params *slack.GetConversationsParameters) ([]slack.Channel, string, error) {
	// Please see https://github.com/korotovsky/slack-mcp-server/issues/73
	// It seems that `conversations.list` works with `xoxp` tokens within Enterprise Grid setups
	// and if `xoxc`/`xoxd` defined we fallback to edge client.
	// In non Enterprise Grid setups we always use `conversations.list` api as it accepts both token types wtf.
	if c.isEnterprise {
		if c.isOAuth {
			return c.slackClient.GetConversationsContext(ctx, params)
		} else {
			edgeChannels, _, err := c.edgeClient.GetConversationsContext(ctx, nil)
			if err != nil {
				return nil, "", err
			}

			var channels []slack.Channel
			for _, ec := range edgeChannels {
				if params != nil && params.ExcludeArchived && ec.IsArchived {
					continue
				}

				channels = append(channels, slack.Channel{
					IsGeneral: ec.IsGeneral,
					GroupConversation: slack.GroupConversation{
						Conversation: slack.Conversation{
							ID:                 ec.ID,
							IsIM:               ec.IsIM,
							IsMpIM:             ec.IsMpIM,
							IsPrivate:          ec.IsPrivate,
							Created:            slack.JSONTime(ec.Created.Time().UnixMilli()),
							Unlinked:           ec.Unlinked,
							NameNormalized:     ec.NameNormalized,
							IsShared:           ec.IsShared,
							IsExtShared:        ec.IsExtShared,
							IsOrgShared:        ec.IsOrgShared,
							IsPendingExtShared: ec.IsPendingExtShared,
							NumMembers:         ec.NumMembers,
						},
						Name:       ec.Name,
						IsArchived: ec.IsArchived,
						Members:    ec.Members,
						Topic: slack.Topic{
							Value: ec.Topic.Value,
						},
						Purpose: slack.Purpose{
							Value: ec.Purpose.Value,
						},
					},
				})
			}

			return channels, "", nil
		}
	}

	return c.slackClient.GetConversationsContext(ctx, params)
}

func (c *MCPSlackClient) GetConversationHistoryContext(ctx context.Context, params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error) {
	return c.slackClient.GetConversationHistoryContext(ctx, params)
}

func (c *MCPSlackClient) GetConversationRepliesContext(ctx context.Context, params *slack.GetConversationRepliesParameters) (msgs []slack.Message, hasMore bool, nextCursor string, err error) {
	return c.slackClient.GetConversationRepliesContext(ctx, params)
}

func (c *MCPSlackClient) SearchContext(ctx context.Context, query string, params slack.SearchParameters) (*slack.SearchMessages, *slack.SearchFiles, error) {
	return c.slackClient.SearchContext(ctx, query, params)
}

func (c *MCPSlackClient) PostMessageContext(ctx context.Context, channelID string, options ...slack.MsgOption) (string, string, error) {
	return c.slackClient.PostMessageContext(ctx, channelID, options...)
}

func (c *MCPSlackClient) ClientUserBoot(ctx context.Context) (*edge.ClientUserBootResponse, error) {
	return c.edgeClient.ClientUserBoot(ctx)
}

func (c *MCPSlackClient) IsEnterprise() bool {
	return c.isEnterprise
}

func (c *MCPSlackClient) AuthResponse() *slack.AuthTestResponse {
	return c.authResponse
}

func (c *MCPSlackClient) Raw() struct {
	Slack *slack.Client
	Edge  *edge.Client
} {
	return struct {
		Slack *slack.Client
		Edge  *edge.Client
	}{
		Slack: c.slackClient,
		Edge:  c.edgeClient,
	}
}

func New(transport string, logger *zap.Logger) *TokenBasedApiProvider {
	// Create base provider
	baseProvider := newBaseProvider(transport, logger)
	
	// Check for environment variable token for backward compatibility
	oauthToken := os.Getenv("SLACK_OAUTH_TOKEN")
	if oauthToken == "" {
		// Fallback to legacy environment variable name
		oauthToken = os.Getenv("SLACK_MCP_XOXP_TOKEN")
	}

	// If token found in environment, create client immediately
	if oauthToken != "" {
		client, err := NewMCPSlackClientFromToken(oauthToken, logger)
		if err != nil {
			logger.Fatal("Failed to create MCP Slack client from environment token", zap.Error(err))
		}
		baseProvider.client = client
		logger.Info("Initialized with OAuth token from environment variables")
	} else {
		logger.Info("No environment OAuth token found - will extract tokens from HTTP Authorization headers")
	}

	return &TokenBasedApiProvider{ApiProvider: baseProvider}
}

// newBaseProvider creates a base ApiProvider without a client
func newBaseProvider(transport string, logger *zap.Logger) *ApiProvider {

	return &ApiProvider{
		transport: transport,
		client:    nil, // Will be set dynamically from tokens
		logger:    logger,

		rateLimiter: limiter.Tier2.Limiter(),

		users:      make(map[string]slack.User),
		usersInv:   map[string]string{},
		// usersCache: usersCache,

		channels:      make(map[string]Channel),
		channelsInv:   map[string]string{},
		// channelsCache: channelsCache,
	}
}

func (tap *TokenBasedApiProvider) RefreshUsersWithContext(ctx context.Context) error {
    client, err := tap.GetClientFromContext(ctx)
    if err != nil {
        return err
    }
    
    // Temporarily set client for refresh
    originalClient := tap.client
    tap.client = client
    defer func() { tap.client = originalClient }()
    
    return tap.RefreshUsers(ctx)
}

func (tap *TokenBasedApiProvider) SetClient(client SlackAPI) {
    tap.ApiProvider.client = client
}

func (ap *ApiProvider) RefreshUsers(ctx context.Context) error {
	var (
		list         []slack.User
		usersCounter = 0
		optionLimit  = slack.GetUsersOptionLimit(1000)
	)

	ap.logger.Debug("RefreshUsers called - fetching from Slack API")

	users, err := ap.client.GetUsersContext(ctx,
		optionLimit,
	)
	ap.logger.Debug("GetUsersContext called") 
	if err != nil {
		ap.logger.Error("Failed to fetch users", zap.Error(err))
		return err
	} else {
		list = append(list, users...)
	}

	for _, user := range users {
		ap.users[user.ID] = user
		ap.usersInv[user.Name] = user.ID
		usersCounter++
	}

	users, err = ap.GetSlackConnect(ctx)
	if err != nil {
		ap.logger.Error("Failed to fetch users from Slack Connect", zap.Error(err))
		return err
	} else {
		list = append(list, users...)
	}

	for _, user := range users {
		ap.users[user.ID] = user
		ap.usersInv[user.Name] = user.ID
		usersCounter++
	}
	ap.logger.Info("Loaded users from Slack API",
        zap.Int("count", usersCounter))

	ap.usersReady = true

	return nil
}

func (ap *ApiProvider) RefreshChannels(ctx context.Context) error {

	channels := ap.GetChannels(ctx, AllChanTypes)

	ap.logger.Info("Loaded channels from Slack API",
        zap.Int("count", len(channels)))
	ap.channelsReady = true

	return nil
}

func (ap *ApiProvider) GetSlackConnect(ctx context.Context) ([]slack.User, error) {
	boot, err := ap.client.ClientUserBoot(ctx)
	if err != nil {
		ap.logger.Error("Failed to fetch client user boot", zap.Error(err))
		return nil, err
	}

	var collectedIDs []string
	for _, im := range boot.IMs {
		if !im.IsShared && !im.IsExtShared {
			continue
		}

		_, ok := ap.users[im.User]
		if !ok {
			collectedIDs = append(collectedIDs, im.User)
		}
	}

	res := make([]slack.User, 0, len(collectedIDs))
	if len(collectedIDs) > 0 {
		usersInfo, err := ap.client.GetUsersInfo(strings.Join(collectedIDs, ","))
		if err != nil {
			ap.logger.Error("Failed to fetch users info for shared IMs", zap.Error(err))
			return nil, err
		}

		for _, u := range *usersInfo {
			res = append(res, u)
		}
	}

	return res, nil
}

func (ap *ApiProvider) GetChannelsType(ctx context.Context, channelType string) []Channel {
	params := &slack.GetConversationsParameters{
		Types:           []string{channelType},
		Limit:           999,
		ExcludeArchived: true,
	}

	var (
		channels []slack.Channel
		chans    []Channel

		nextcur string
		err     error
	)

	for {
		if err := ap.rateLimiter.Wait(ctx); err != nil {
			ap.logger.Error("Rate limiter wait failed", zap.Error(err))
			return nil
		}

		channels, nextcur, err = ap.client.GetConversationsContext(ctx, params)
		ap.logger.Debug("Fetched channels for ",
			zap.String("channelType", channelType),
			zap.Int("count", len(channels)),
		)
		if err != nil {
			ap.logger.Error("Failed to fetch channels", zap.Error(err))
			break
		}

		chans = make([]Channel, 0, len(channels))
		for _, channel := range channels {
			ch := mapChannel(
				channel.ID,
				channel.Name,
				channel.NameNormalized,
				channel.Topic.Value,
				channel.Purpose.Value,
				channel.User,
				channel.Members,
				channel.NumMembers,
				channel.IsIM,
				channel.IsMpIM,
				channel.IsPrivate,
				ap.ProvideUsersMap().Users,
			)
			chans = append(chans, ch)
		}

		if nextcur == "" {
			break
		}

		params.Cursor = nextcur
	}
	return chans
}

func (ap *ApiProvider) GetChannels(ctx context.Context, channelTypes []string) []Channel {
	if len(channelTypes) == 0 {
		channelTypes = AllChanTypes
	}

	var chans []Channel
	for _, t := range AllChanTypes {
		var typeChannels = ap.GetChannelsType(ctx, t)
		chans = append(chans, typeChannels...)
	}

	for _, ch := range chans {
		ap.channels[ch.ID] = ch
		ap.channelsInv[ch.Name] = ch.ID
	}

	var res []Channel
	for _, t := range channelTypes {
		for _, channel := range ap.channels {
			if t == "public_channel" && !channel.IsPrivate {
				res = append(res, channel)
			}
			if t == "private_channel" && channel.IsPrivate {
				res = append(res, channel)
			}
			if t == "im" && channel.IsIM {
				res = append(res, channel)
			}
			if t == "mpim" && channel.IsMpIM {
				res = append(res, channel)
			}
		}
	}

	return res
}

func (ap *ApiProvider) ProvideUsersMap() *UsersCache {
	return &UsersCache{
		Users:    ap.users,
		UsersInv: ap.usersInv,
	}
}

func (ap *ApiProvider) ProvideChannelsMaps() *ChannelsCache {
	return &ChannelsCache{
		Channels:    ap.channels,
		ChannelsInv: ap.channelsInv,
	}
}

func (ap *ApiProvider) IsReady() (bool, error) {
	if !ap.usersReady {
		return false, ErrUsersNotReady
	}
	if !ap.channelsReady {
		return false, ErrChannelsNotReady
	}
	return true, nil
}

func (ap *ApiProvider) ServerTransport() string {
	return ap.transport
}

func (ap *ApiProvider) Slack() SlackAPI {
	return ap.client
}

func mapChannel(
	id, name, nameNormalized, topic, purpose, user string,
	members []string,
	numMembers int,
	isIM, isMpIM, isPrivate bool,
	usersMap map[string]slack.User,
) Channel {
	channelName := name
	finalPurpose := purpose
	finalTopic := topic
	finalMemberCount := numMembers

	if isIM {
		finalMemberCount = 2
		if u, ok := usersMap[user]; ok {
			channelName = "@" + u.Name
			finalPurpose = "DM with " + u.RealName
		} else {
			channelName = "@" + user
			finalPurpose = "DM with " + user
		}
		finalTopic = ""
	} else if isMpIM {
		if len(members) > 0 {
			finalMemberCount = len(members)
			var userNames []string
			for _, uid := range members {
				if u, ok := usersMap[uid]; ok {
					userNames = append(userNames, u.RealName)
				} else {
					userNames = append(userNames, uid)
				}
			}
			channelName = "@" + nameNormalized
			finalPurpose = "Group DM with " + strings.Join(userNames, ", ")
			finalTopic = ""
		}
	} else {
		channelName = "#" + nameNormalized
	}

	return Channel{
		ID:          id,
		Name:        channelName,
		Topic:       finalTopic,
		Purpose:     finalPurpose,
		MemberCount: finalMemberCount,
		IsIM:        isIM,
		IsMpIM:      isMpIM,
		IsPrivate:   isPrivate,
	}
}
