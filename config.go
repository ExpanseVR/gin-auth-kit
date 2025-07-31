package auth

import (
	"time"

	"github.com/gorilla/sessions"
)

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

// BFFAuthOptions represents configuration for BFF authentication
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

// AuthOptions represents configuration for traditional authentication
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

	// Callback Functions
	FindUserByEmail FindUserByEmailFunc
	FindUserByID    FindUserByIDFunc
} 