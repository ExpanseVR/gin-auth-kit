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
  JWT   *JWTService
  BFF   *BFFService
  OAuth *OAuthService
}

func createSessionStore(sessionSecret, sessionDomain string, sessionMaxAge int, sessionSecure bool) sessions.Store {
	sessionStore := sessions.NewCookieStore([]byte(sessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   sessionDomain,
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		Secure:   sessionSecure,
		SameSite: http.SameSiteLaxMode,
	}
	return sessionStore
}

// NewAuthService creates a traditional AuthService (stateless/middleware-based)
// Creates: Optional JWT service + optional OAuth service
// Use for: Traditional APIs, mobile apps, OAuth-only auth, stateless systems
func NewAuthService(opts *AuthOptions) (*AuthService, error) {
	if err := opts.ValidateAuthOptions(); err != nil {
		return nil, fmt.Errorf("invalid AuthOptions: %w", err)
	}

	sessionStore := createSessionStore(opts.SessionSecret, opts.SessionDomain, opts.SessionMaxAge, opts.SessionSecure)

	var jwtService *JWTService
	if opts.JWTSecret != "" {
		jwtMiddleware, err := NewJWTMiddleware(&JWTOptions{
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
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT service: %w", err)
		}

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

	sessionStore := createSessionStore(opts.SessionSecret, opts.SessionDomain, opts.SessionMaxAge, opts.SessionSecure)

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
