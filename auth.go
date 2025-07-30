package auth

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

type JWTService struct {
	Middleware AuthMiddleware
}

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

// NewAuthService creates a traditional AuthService (stateless/middleware-based)
// Creates: Optional JWT service + optional OAuth service
// Use for: Traditional APIs, mobile apps, OAuth-only auth, stateless systems
func NewAuthService(opts *AuthOptions) (*AuthService, error) {
	if opts == nil {
		return nil, fmt.Errorf("AuthOptions cannot be nil")
	}

	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}

	var jwtService *JWTService
	if opts.JWTSecret != "" {
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

		jwtService = &JWTService{
			Middleware: jwtMiddleware,
		}
	}

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
		BFF:          nil,
		OAuth:        oauthService,
	}, nil
}

// NewBFFAuthService creates a BFF-centric AuthService (session-based with JWT exchange)
// Creates: BFF service (always) + optional OAuth service
// Use for: Backend-for-Frontend pattern, web apps, session-to-JWT conversion
func NewBFFAuthService(opts *BFFAuthOptions) (*AuthService, error) {
	if err := opts.ValidateBFFAuthOptions(); err != nil {
		return nil, fmt.Errorf("invalid BFF configuration: %w", err)
	}

	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: http.SameSiteLaxMode,
	}

	sessionService := opts.SessionService
	jwtExchangeService := NewJWTExchangeService(opts.JWTSecret, sessionService, opts.JWTExpiry)
	bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, opts.SIDCookieName)

	bffService := &BFFService{
		Sessions:   sessionService,
		Exchange:   jwtExchangeService,
		Middleware: bffMiddleware,
	}

	var oauthService *OAuthService
	if opts.OAuth != nil {
		if opts.OAuth.SessionStore == nil {
			opts.OAuth.SessionStore = sessionStore
		}
		oauthService = NewOAuthService(opts.OAuth)
	}

	return &AuthService{
		SessionStore: sessionStore,
		JWT:          nil,
		BFF:          bffService,
		OAuth:        oauthService,
	}, nil
}
