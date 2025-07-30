package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

// UserInfo represents user data returned by callback functions
type UserInfo struct {
	ID           uint   `json:"id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"` // Never expose password hash in JSON
}

// UserFinder callback function types
type FindUserByEmailFunc func(email string) (UserInfo, error)
type FindUserByIDFunc func(id uint) (UserInfo, error)

// AuthMiddleware defines the interface that all auth middleware must implement
// This allows for different auth strategies (JWT, session, etc.)
type AuthMiddleware interface {
	MiddlewareFunc() gin.HandlerFunc
	LoginHandler() gin.HandlerFunc
	LogoutHandler() gin.HandlerFunc
	RefreshHandler() gin.HandlerFunc
}

// OAuthProvider represents configuration for an OAuth provider
type OAuthProvider struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// OAuthConfig represents the overall OAuth configuration
type OAuthConfig struct {
	Providers    map[string]OAuthProvider `json:"providers"`
	SessionStore sessions.Store           `json:"-"`
	BaseURL      string                   `json:"base_url"`
	SuccessURL   string                   `json:"success_url"`
	FailureURL   string                   `json:"failure_url"`
	
	// User management callbacks
	FindUserByEmail FindUserByEmailFunc `json:"-"`
	FindUserByID    FindUserByIDFunc    `json:"-"`
}

// SessionService defines the interface for session management
type SessionService interface {
	CreateSession(user UserInfo, expiry time.Duration) (string, error)
	GetSession(sid string) (UserInfo, error)
	DeleteSession(sid string) error
	ValidateSession(sid string) (UserInfo, error)
}

// SessionExchangeService defines the interface for session-to-JWT exchange
type SessionExchangeService interface {
	ExchangeSessionForJWT(sid string) (string, error)
	RefreshSessionJWT(sid string) (string, error)
}

// BFFAuthMiddleware defines the interface for BFF authentication middleware
type BFFAuthMiddleware interface {
	RequireSession() gin.HandlerFunc
	RequireValidSession() gin.HandlerFunc
	OptionalSession() gin.HandlerFunc
}

type BFFAuthOptions struct {
	// Session configuration
	SessionSecret string
	SessionMaxAge int
	SessionDomain string
	SessionSecure bool
	
	// JWT configuration  
	JWTSecret     string
	JWTExpiry     time.Duration
	
	// Cookie configuration
	SIDCookieName string
	SIDCookiePath string
	
	// Session service (provided by implementing project)
	SessionService SessionService
	
	// User callbacks
	FindUserByEmail FindUserByEmailFunc
	FindUserByID    FindUserByIDFunc
	
	// OAuth configuration (optional)
	OAuth *OAuthConfig
}

func (opts *BFFAuthOptions) ValidateBFFAuthOptions() error {
	if opts == nil {
		return errors.New("BFFAuthOptions cannot be nil")
	}

	if opts.SessionSecret == "" {
		return errors.New("SessionSecret is required")
	}

	if opts.SessionMaxAge <= 0 {
		return errors.New("SessionMaxAge must be positive")
	}

	if opts.JWTSecret == "" {
		return errors.New("JWTSecret is required")
	}

	if opts.JWTExpiry <= 0 {
		return errors.New("JWTExpiry must be positive")
	}

	if opts.SessionService == nil {
		return errors.New("SessionService is required")
	}

	if opts.SIDCookieName == "" {
		opts.SIDCookieName = "sid" // Set default
	}

	if opts.SIDCookiePath == "" {
		opts.SIDCookiePath = "/" // Set default
	}

	if opts.FindUserByEmail == nil {
		return errors.New("FindUserByEmail callback is required")
	}

	if opts.FindUserByID == nil {
		return errors.New("FindUserByID callback is required")
	}

	if opts.OAuth != nil {
		if err := opts.OAuth.ValidateOAuthConfig(); err != nil {
			return fmt.Errorf("OAuth configuration invalid: %w", err)
		}
	}

	return nil
}

func (config *OAuthConfig) ValidateOAuthConfig() error {
	if config == nil {
		return errors.New("OAuthConfig cannot be nil")
	}

	if len(config.Providers) == 0 {
		return errors.New("at least one OAuth provider is required")
	}

	for name, provider := range config.Providers {
		if err := provider.ValidateOAuthProvider(); err != nil {
			return fmt.Errorf("provider %s: %w", name, err)
		}
	}

	if config.BaseURL == "" {
		return errors.New("BaseURL is required")
	}

	if config.SuccessURL == "" {
		return errors.New("SuccessURL is required")
	}

	if config.FailureURL == "" {
		return errors.New("FailureURL is required")
	}

	return nil
}

func (provider *OAuthProvider) ValidateOAuthProvider() error {
	if provider.ClientID == "" {
		return errors.New("ClientID is required")
	}

	if provider.ClientSecret == "" {
		return errors.New("ClientSecret is required")
	}

	if provider.RedirectURL == "" {
		return errors.New("RedirectURL is required")
	}

	if _, err := url.Parse(provider.RedirectURL); err != nil {
		return fmt.Errorf("RedirectURL must be a valid URL: %w", err)
	}

	// Validate scopes (optional but if provided, should not be empty)
	if len(provider.Scopes) > 0 {
		for i, scope := range provider.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("scope %d cannot be empty", i)
			}
		}
	}

	return nil
}

type AuthOptions struct {
	// JWT Configuration
	JWTSecret           string
	JWTRealm           string
	TokenExpireTime    time.Duration
	RefreshExpireTime  time.Duration
	IdentityKey        string

	// Session Configuration  
	SessionSecret string
	SessionMaxAge int
	SessionDomain string
	SessionSecure bool
	SessionSameSite string

	// OAuth Configuration
	OAuth *OAuthConfig

	// Security Settings
	BcryptCost int

	// Callback Functions
	FindUserByEmail FindUserByEmailFunc
	FindUserByID    FindUserByIDFunc
} 