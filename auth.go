package auth

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

// JWTService groups JWT-related functionality
type JWTService struct {
	Middleware AuthMiddleware
}

// BFFService groups all BFF-related services
type BFFService struct {
	Sessions   SessionService
	Exchange   *JWTExchangeService
	Middleware *BFFAuthMiddleware
}

// AuthService is the main service that provides authentication functionality
type AuthService struct {
	// Core services (always present)
	SessionStore sessions.Store
	
	// Optional services (nil if not configured)
	JWT   *JWTService    // nil in BFF-only mode
	BFF   *BFFService    // nil in JWT-only mode
	OAuth *OAuthService  // nil if no OAuth configured
}

// NewAuthService creates a new AuthService with JWT support
func NewAuthService(opts *AuthOptions) (*AuthService, error) {
	if opts == nil {
		return nil, fmt.Errorf("AuthOptions cannot be nil")
	}

	// Create session store for OAuth state management
	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}

	// Create JWT middleware
	jwtMiddleware := NewJWTMiddleware(&JWTOptions{
		Realm:             opts.JWTRealm,
		Key:               []byte(opts.JWTSecret),
		Timeout:           opts.TokenExpireTime,
		MaxRefresh:        opts.RefreshExpireTime,
		IdentityKey:       opts.IdentityKey,
		FindUserByEmail:   opts.FindUserByEmail,
		FindUserByID:      opts.FindUserByID,
		SessionSecure:     opts.SessionSecure,
		SessionDomain:     opts.SessionDomain,
		SessionSameSite:   opts.SessionSameSite,
	})

	// Create JWT service group
	jwtService := &JWTService{
		Middleware: jwtMiddleware,
	}

	// Create OAuth service if configured
	var oauthService *OAuthService
	if opts.OAuth != nil {
		if opts.OAuth.SessionStore == nil {
			opts.OAuth.SessionStore = sessionStore
		}
		oauthService = NewOAuthService(opts.OAuth)
	}

	return &AuthService{
		SessionStore: sessionStore,
		JWT:          jwtService,
		BFF:          nil, // Not available in JWT mode
		OAuth:        oauthService,
	}, nil
}

// NewBFFAuthService creates a new AuthService with BFF support
func NewBFFAuthService(opts *BFFAuthOptions) (*AuthService, error) {
	if err := opts.ValidateBFFAuthOptions(); err != nil {
		return nil, fmt.Errorf("invalid BFF configuration: %w", err)
	}

	// Create session store for OAuth state management
	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}

	// Use the provided SessionService
	sessionService := opts.SessionService
	jwtExchangeService := NewJWTExchangeService(opts.JWTSecret, sessionService, opts.JWTExpiry)
	bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, opts.SIDCookieName)

	// Create BFF service group
	bffService := &BFFService{
		Sessions:   sessionService,
		Exchange:   jwtExchangeService,
		Middleware: bffMiddleware,
	}

	// Create OAuth service if configured
	var oauthService *OAuthService
	if opts.OAuth != nil {
		if opts.OAuth.SessionStore == nil {
			opts.OAuth.SessionStore = sessionStore
		}
		oauthService = NewOAuthService(opts.OAuth)
	}

	return &AuthService{
		SessionStore: sessionStore,
		JWT:          nil, // Not available in BFF mode
		BFF:          bffService,
		OAuth:        oauthService,
	}, nil
}
