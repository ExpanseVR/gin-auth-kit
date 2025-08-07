package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/rs/zerolog/log"
)

var (
	ErrProviderNotFound    = errors.New("oauth provider not found")
	ErrNotImplemented      = errors.New("oauth feature not implemented yet")
	ErrInvalidProvider     = errors.New("invalid oauth provider configuration")
	ErrUnsupportedProvider = errors.New("unsupported oauth provider")
	ErrUserNotFound        = errors.New("user not found")
)

func createGothProvider(name string, provider types.OAuthProvider) (goth.Provider, error) {
	if err := provider.ValidateOAuthProvider(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	switch strings.ToLower(name) {
	case "google":
		return google.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	case "github":
		return github.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	case "facebook":
		return facebook.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, name)
	}
}

// OAuthService handles OAuth authentication
type OAuthService struct {
	Providers    map[string]goth.Provider
	BaseURL      string
	SuccessURL   string
	FailureURL   string
	FindUserByEmail types.FindUserByEmailFunc
	FindUserByID    types.FindUserByIDFunc
	mu           sync.RWMutex // Protects the Providers map
}

func NewOAuthService(config *types.OAuthConfig) *OAuthService {
	if config == nil {
		return nil
	}

	service := &OAuthService{
		Providers:    make(map[string]goth.Provider),
		BaseURL:      config.BaseURL,
		SuccessURL:   config.SuccessURL,
		FailureURL:   config.FailureURL,
		FindUserByEmail: config.FindUserByEmail,
		FindUserByID:    config.FindUserByID,
	}

	// Initialize providers from configuration
	var failedProviders []string
	for name, providerConfig := range config.Providers {
		provider, err := createGothProvider(name, providerConfig)
		if err != nil {
			failedProviders = append(failedProviders, name)
			if config.FailOnProviderError {
				log.Error().Err(err).Str("provider", name).Msg("Failed to initialize OAuth provider - failing fast")
				return nil
			}
			// Log the error but continue with other providers
			log.Warn().Err(err).Str("provider", name).Msg("Failed to initialize OAuth provider")
			continue
		}
		service.Providers[name] = provider
	}

	if len(failedProviders) > 0 {
		log.Warn().
			Strs("failed_providers", failedProviders).
			Int("total_providers", len(config.Providers)).
			Int("successful_providers", len(service.Providers)).
			Msg("Some OAuth providers failed to initialize")
	}

	// Register all providers with goth at once to avoid overwriting
	if len(service.Providers) > 0 {
		providers := make([]goth.Provider, 0, len(service.Providers))
		for _, provider := range service.Providers {
			providers = append(providers, provider)
		}
		goth.UseProviders(providers...)
	}

	return service
}

func (auth *OAuthService) RegisterProvider(name string, provider goth.Provider) {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	auth.Providers[name] = provider

	// Re-register all providers with goth to include the new one
	providers := make([]goth.Provider, 0, len(auth.Providers))
	for _, p := range auth.Providers {
		providers = append(providers, p)
	}
	goth.UseProviders(providers...)
}

func (auth *OAuthService) GetProvider(name string) (goth.Provider, error) {
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	provider, exists := auth.Providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

func (auth *OAuthService) BeginAuthHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		providerName := ctx.Param("provider")
		if providerName == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		_, err := auth.GetProvider(providerName)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		gothic.BeginAuthHandler(ctx.Writer, ctx.Request)
	}
}

// CompleteAuthHandler handles the OAuth callback
func (auth *OAuthService) CompleteAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		_, err := auth.GetProvider(providerName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
			return
		}

		userInfo, err := auth.MapGothUserToUserInfo(gothUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User mapping failed"})
			return
		}

		c.JSON(http.StatusOK, userInfo)
	}
}

func (auth *OAuthService) MapGothUserToUserInfo(gothUser goth.User) (types.UserInfo, error) {
	if gothUser.Email == "" {
		return types.UserInfo{}, errors.New("email is required")
	}

	// Start with existing user data if available, or create new user info
	var userInfo types.UserInfo
	if auth.FindUserByEmail != nil {
		existingUser, err := auth.FindUserByEmail(gothUser.Email)
		if err == nil {
			userInfo = existingUser
		} else {
			userInfo = types.UserInfo{
				Email: gothUser.Email,
				Role:  "user", // Default role for OAuth users. TODO: Make this configurable.
			}
		}
	} else {
		userInfo = types.UserInfo{
			Email: gothUser.Email,
			Role:  "user", // Default role for OAuth users. TODO: Make this configurable.
		}
	}

	if gothUser.Name != "" {
		names := strings.SplitN(gothUser.Name, " ", 2)
		if len(names) > 0 {
			userInfo.FirstName = names[0]
		}
		if len(names) > 1 {
			userInfo.LastName = names[1]
		}
	}

	// Initialize CustomFields if nil
	if userInfo.CustomFields == nil {
		userInfo.CustomFields = make(map[string]any)
	}

	addGothUserFields(gothUser, &userInfo)

	return userInfo, nil
}

func addGothUserFields(gothUser goth.User, userInfo *types.UserInfo) {
	// Store frontend-safe OAuth data in CustomFields
	if gothUser.UserID != "" {
		userInfo.CustomFields["oauth_user_id"] = gothUser.UserID
	}
	if gothUser.Name != "" {
		userInfo.CustomFields["goth_name"] = gothUser.Name
	}
	
	if gothUser.NickName != "" {
		userInfo.CustomFields["nickname"] = gothUser.NickName
	}
	if gothUser.Description != "" {
		userInfo.CustomFields["description"] = gothUser.Description
	}
	if gothUser.AvatarURL != "" {
		userInfo.CustomFields["avatar_url"] = gothUser.AvatarURL
	}
	if gothUser.Location != "" {
		userInfo.CustomFields["location"] = gothUser.Location
	}
}
