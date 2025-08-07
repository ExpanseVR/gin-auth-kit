package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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

func validateProvider(name string, provider OAuthProvider) error {
	if provider.ClientID == "" {
		return fmt.Errorf("%s: ClientID is required", name)
	}
	if provider.ClientSecret == "" {
		return fmt.Errorf("%s: ClientSecret is required", name)
	}
	if provider.RedirectURL == "" {
		return fmt.Errorf("%s: RedirectURL is required", name)
	}

	// Validate redirect URL format
	if _, err := url.Parse(provider.RedirectURL); err != nil {
		return fmt.Errorf("%s: RedirectURL must be a valid URL: %v", name, err)
	}

	if len(provider.Scopes) > 0 {
		for i, scope := range provider.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("%s: scope %d cannot be empty", name, i)
			}
		}
	}

	return nil
}

func createGothProvider(name string, provider OAuthProvider) (goth.Provider, error) {
	if err := validateProvider(name, provider); err != nil {
		return nil, err
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

type OAuthService struct {
	Providers map[string]goth.Provider
	config    *OAuthConfig
}

func NewOAuthService(config *OAuthConfig) *OAuthService {
	if config == nil {
		return nil
	}

	service := &OAuthService{
		Providers: make(map[string]goth.Provider),
		config:    config,
	}

	// Initialize providers from configuration
	for name, providerConfig := range config.Providers {
		provider, err := createGothProvider(name, providerConfig)
		if err != nil {
			// Log the error but continue with other providers
			log.Warn().Err(err).Str("provider", name).Msg("Failed to initialize OAuth provider")
			continue
		}
		service.Providers[name] = provider
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
	auth.Providers[name] = provider

	// Re-register all providers with goth to include the new one
	providers := make([]goth.Provider, 0, len(auth.Providers))
	for _, p := range auth.Providers {
		providers = append(providers, p)
	}
	goth.UseProviders(providers...)
}

func (auth *OAuthService) GetProvider(name string) (goth.Provider, error) {
	provider, exists := auth.Providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

func (auth *OAuthService) BeginAuthHandler() gin.HandlerFunc {
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

		gothic.BeginAuthHandler(c.Writer, c.Request)
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

func (auth *OAuthService) MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error) {
	if gothUser.Email == "" {
		return UserInfo{}, errors.New("email is required")
	}

	if auth.config != nil && auth.config.FindUserByEmail != nil {
		existingUser, err := auth.config.FindUserByEmail(gothUser.Email)
		if err == nil {
			return existingUser, nil
		}
	}

	userInfo := UserInfo{
		Email: gothUser.Email,
		Role:  "user", // Default role for OAuth users. TODO: Make this configurable.
	}

	// Try to convert UserID to uint if it exists
	if gothUser.UserID != "" {
		if userID, err := strconv.ParseUint(gothUser.UserID, 10, 32); err == nil {
			userInfo.ID = uint(userID)
		}
	}

	// Extract first and last name from the Name field if available
	if gothUser.Name != "" {
		names := strings.SplitN(gothUser.Name, " ", 2)
		if len(names) > 0 {
			userInfo.FirstName = names[0]
		}
		if len(names) > 1 {
			userInfo.LastName = names[1]
		}
	}

	// Add custom fields from Goth user
	if userInfo.CustomFields == nil {
		userInfo.CustomFields = make(map[string]any)
	}

	addGothUserFields(gothUser, &userInfo)

	return userInfo, nil
}

func addGothUserFields(gothUser goth.User, userInfo *UserInfo) {
	// Store frontend-safe OAuth data in CustomFields
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
