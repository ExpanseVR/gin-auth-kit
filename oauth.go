package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
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

// OAuthService provides OAuth authentication functionality
type OAuthService struct {
	Providers    map[string]goth.Provider
	sessionStore sessions.Store
	config       *OAuthConfig
}

// NewOAuthService creates a new OAuth service instance
func NewOAuthService(config *OAuthConfig) *OAuthService {
	if config == nil {
		return nil
	}
	
	service := &OAuthService{
		Providers:    make(map[string]goth.Provider),
		sessionStore: config.SessionStore,
		config:       config,
	}
	
	// Initialize providers from configuration
	for name, providerConfig := range config.Providers {
		provider, err := createGothProvider(name, providerConfig)
		if err != nil {
			// Log error but continue with other providers
			continue
		}
		service.Providers[name] = provider
	}
	
	return service
}

// RegisterProvider registers a new OAuth provider
func (o *OAuthService) RegisterProvider(name string, provider goth.Provider) {
	o.Providers[name] = provider
	goth.UseProviders(provider)
}

// GetProvider retrieves a registered OAuth provider
func (o *OAuthService) GetProvider(name string) (goth.Provider, error) {
	provider, exists := o.Providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// BeginAuthHandler handles the beginning of OAuth authentication
func (o *OAuthService) BeginAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get provider name from URL parameter
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		// Validate provider exists
		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		// Use Gothic to begin auth
		gothic.BeginAuthHandler(c.Writer, c.Request)
	}
}

// CompleteAuthHandler handles the OAuth callback
func (o *OAuthService) CompleteAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get provider name from URL parameter
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		// Validate provider exists
		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		// Use Gothic to complete auth
		gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
			return
		}

		// Map to our UserInfo structure
		userInfo, err := o.MapGothUserToUserInfo(gothUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User mapping failed"})
			return
		}

		// Return user info (in real implementation, you'd create a session/JWT here)
		c.JSON(http.StatusOK, userInfo)
	}
}

// MapGothUserToUserInfo maps a Goth user to our UserInfo structure
func (o *OAuthService) MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error) {
	// Validate required fields
	if gothUser.Email == "" {
		return UserInfo{}, errors.New("email is required")
	}

	// Try to find existing user by email if callback is provided
	if o.config != nil && o.config.FindUserByEmail != nil {
		existingUser, err := o.config.FindUserByEmail(gothUser.Email)
		if err == nil {
			// User exists, return existing user info
			return existingUser, nil
		}
		// If user not found, we'll create a new one
	}

	// For new users, we need to create them
	// This would typically involve calling a user creation callback
	// For now, we'll return a basic user structure
	// TODO: Add user creation callback to OAuthConfig
	
	userInfo := UserInfo{
		Email: gothUser.Email,
		Role:  "user", // Default role for OAuth users
	}

	// Try to extract ID from Goth user data
	if gothUser.UserID != "" {
		// Try to parse as uint
		if id, err := strconv.ParseUint(gothUser.UserID, 10, 32); err == nil {
			userInfo.ID = uint(id)
		}
	}

	// If no ID found, we'll need to create the user
	// For now, return the user info without ID
	// The actual user creation should be handled by the application

	return userInfo, nil
} 