package auth

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
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

// OAuthService defines the interface for OAuth operations
type OAuthService interface {
	// Provider management
	RegisterProvider(name string, provider goth.Provider)
	GetProvider(name string) (goth.Provider, error)
	
	// OAuth flow handlers
	BeginAuthHandler() gin.HandlerFunc
	CompleteAuthHandler() gin.HandlerFunc
	
	// User mapping
	MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error)
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