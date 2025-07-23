package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

// OAuth-related errors
var (
	ErrProviderNotFound = errors.New("oauth provider not found")
	ErrNotImplemented   = errors.New("oauth feature not implemented yet")
	ErrInvalidProvider  = errors.New("invalid oauth provider configuration")
	ErrUnsupportedProvider = errors.New("unsupported oauth provider")
	ErrUserNotFound     = errors.New("user not found")
)

// validateProvider validates OAuth provider configuration
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
	
	// Validate scopes (optional but if provided, should not be empty)
	if len(provider.Scopes) > 0 {
		for i, scope := range provider.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("%s: scope %d cannot be empty", name, i)
			}
		}
	}
	
	return nil
}

// createGothProvider creates a Goth provider from OAuthProvider configuration
func createGothProvider(name string, provider OAuthProvider) (goth.Provider, error) {
	// Validate provider configuration first
	if err := validateProvider(name, provider); err != nil {
		return nil, err
	}
	
	// Create provider based on name
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

// oauthService implements the OAuthService interface
type oauthService struct {
	providers    map[string]goth.Provider
	sessionStore sessions.Store
	config       *OAuthConfig
}

// NewOAuthService creates a new OAuth service instance
func NewOAuthService(config *OAuthConfig) OAuthService {
	service := &oauthService{
		providers:    make(map[string]goth.Provider),
		sessionStore: config.SessionStore,
		config:       config,
	}
	
	// Initialize providers from configuration
	for name, providerConfig := range config.Providers {
		gothProvider, err := createGothProvider(name, providerConfig)
		if err != nil {
			// Log error but continue with other providers
			// TODO: Add proper logging here
			continue
		}
		service.RegisterProvider(name, gothProvider)
	}
	
	return service
}

// RegisterProvider registers a new OAuth provider
func (o *oauthService) RegisterProvider(name string, provider goth.Provider) {
	o.providers[name] = provider
	goth.UseProviders(provider)
}

// GetProvider retrieves a registered OAuth provider
func (o *oauthService) GetProvider(name string) (goth.Provider, error) {
	provider, exists := o.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// BeginAuthHandler handles the beginning of OAuth authentication
func (o *oauthService) BeginAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement OAuth initiation logic
		c.JSON(501, gin.H{"error": "OAuth BeginAuthHandler not implemented yet"})
	}
}

// CompleteAuthHandler handles the OAuth callback
func (o *oauthService) CompleteAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement OAuth callback logic
		c.JSON(501, gin.H{"error": "OAuth CompleteAuthHandler not implemented yet"})
	}
}

// MapGothUserToUserInfo maps a Goth user to our UserInfo structure
func (o *oauthService) MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error) {
	// TODO: Implement user mapping logic
	return UserInfo{}, ErrNotImplemented
} 