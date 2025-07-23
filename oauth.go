package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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

// Session management helper functions

// createSessionStore creates a new session store for OAuth operations
func createSessionStore(secret string) sessions.Store {
	store := sessions.NewCookieStore([]byte(secret))
	store.Options = &sessions.Options{
		MaxAge:   86400 * 30, // 30 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	}
	return store
}

// generateSessionKey generates a secure session key for OAuth state
func generateSessionKey() string {
	// Generate a random 32-byte key
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to timestamp-based key if crypto/rand fails
		return fmt.Sprintf("oauth_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("oauth_%x", bytes)
}

// cleanupSession removes OAuth-related session data
func cleanupSession(session *sessions.Session) {
	delete(session.Values, "oauth_state")
	delete(session.Values, "provider")
}

// validateSession validates that a session contains required OAuth data
func validateSession(session *sessions.Session) error {
	if session == nil {
		return errors.New("session is nil")
	}
	
	// Check if session has required OAuth data
	if _, ok := session.Values["user_id"]; !ok {
		return errors.New("session missing user_id")
	}
	
	if _, ok := session.Values["email"]; !ok {
		return errors.New("session missing email")
	}
	
	return nil
}

// oauthService implements the OAuthService interface
type oauthService struct {
	providers    map[string]goth.Provider
	sessionStore sessions.Store
	config       *OAuthConfig
}

// NewOAuthService creates a new OAuth service instance
func NewOAuthService(config *OAuthConfig) OAuthService {
	if config == nil {
		return nil
	}
	
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
		// Get provider name from URL parameter
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(400, gin.H{"error": "Provider name is required"})
			return
		}

		// Get the provider (validate it exists)
		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(400, gin.H{"error": "Provider not found"})
			return
		}

		// Set the provider for this request
		c.Set("provider", providerName)
		
		// Use Gothic to begin the OAuth flow
		gothic.BeginAuthHandler(c.Writer, c.Request)
	}
}

// CompleteAuthHandler handles the OAuth callback
func (o *oauthService) CompleteAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get provider name from URL parameter
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(400, gin.H{"error": "Provider name is required"})
			return
		}

		// Get the provider (validate it exists)
		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(400, gin.H{"error": "Provider not found"})
			return
		}

		// Set the provider for this request
		c.Set("provider", providerName)

		// Use Gothic to complete the OAuth flow
		gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			// Redirect to failure URL or return error
			if o.config.FailureURL != "" {
				c.Redirect(302, o.config.FailureURL)
			} else {
				c.JSON(400, gin.H{"error": "OAuth authentication failed", "details": err.Error()})
			}
			return
		}

		// Map Goth user to our UserInfo format
		userInfo, err := o.MapGothUserToUserInfo(gothUser)
		if err != nil {
			if o.config.FailureURL != "" {
				c.Redirect(302, o.config.FailureURL)
			} else {
				c.JSON(400, gin.H{"error": "Failed to process user data", "details": err.Error()})
			}
			return
		}

		// Store user info in session for later use
		sessionKey := generateSessionKey()
		session, err := o.sessionStore.New(c.Request, sessionKey)
		if err == nil {
			session.Values["user_id"] = userInfo.ID
			session.Values["email"] = userInfo.Email
			session.Values["role"] = userInfo.Role
			session.Values["provider"] = providerName
			session.Values["oauth_state"] = "authenticated"
			session.Save(c.Request, c.Writer)
		}

		// Redirect to success URL or return user data
		if o.config.SuccessURL != "" {
			c.Redirect(302, o.config.SuccessURL)
		} else {
			c.JSON(200, gin.H{
				"message": "OAuth authentication successful",
				"user":    userInfo,
				"provider": providerName,
			})
		}
	}
}

// MapGothUserToUserInfo maps a Goth user to our UserInfo structure
func (o *oauthService) MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error) {
	// Validate required fields
	if gothUser.Email == "" {
		return UserInfo{}, fmt.Errorf("oauth user email is required")
	}

	// Try to find existing user by email first
	if o.config.FindUserByEmail != nil {
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
		Role:  "customer", // Default role for OAuth users
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