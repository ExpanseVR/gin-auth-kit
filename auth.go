package auth

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

// AuthMiddleware defines the interface that all auth middleware must implement
// This allows for different auth strategies (JWT, session, etc.)
type AuthMiddleware interface {
	MiddlewareFunc() gin.HandlerFunc
	LoginHandler() gin.HandlerFunc
	LogoutHandler() gin.HandlerFunc
	RefreshHandler() gin.HandlerFunc
}

type AuthService struct {
	middleware         AuthMiddleware
	sessionStore       sessions.Store
	oauthService       OAuthService
	sessionService     SessionService
	jwtExchangeService SessionExchangeService
	bffMiddleware      BFFAuthMiddleware
}

// NewAuthService creates a new authentication service
// This is the main entry point - use this instead of creating middleware directly
func NewAuthService(opts *AuthOptions) (*AuthService, error) {
	// Validate required callback functions
	if opts.FindUserByEmail == nil {
		return nil, fmt.Errorf("FindUserByEmail callback is required")
	}
	if opts.FindUserByID == nil {
		return nil, fmt.Errorf("FindUserByID callback is required")
	}

	// Initialize JWT middleware as primary auth method
	jwtMiddleware, err := newJWTMiddleware(opts)
	if err != nil {
		return nil, err
	}

	// Initialize session store for OAuth and other stateful auth flows
	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: parseSameSite(opts.SessionSameSite),
	}

	// Initialize OAuth service if configuration is provided
	var oauthService OAuthService
	if opts.OAuth != nil {
		// Use the session store from OAuth config if provided, otherwise use the default one
		if opts.OAuth.SessionStore == nil {
			opts.OAuth.SessionStore = sessionStore
		}
		oauthService = NewOAuthService(opts.OAuth)
	}

	// Initialize BFF services
	sessionService := NewSessionService(sessionStore)
	jwtExchangeService := NewJWTExchangeService(opts.JWTSecret, sessionService, opts.TokenExpireTime)
	bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, "sid")

	return &AuthService{
		middleware:         jwtMiddleware,
		sessionStore:       sessionStore,
		oauthService:       oauthService,
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		bffMiddleware:      bffMiddleware,
	}, nil
}

// NewBFFAuthService creates a new BFF authentication service
// This is the main entry point for BFF-only configurations
func NewBFFAuthService(opts *BFFAuthOptions) (*AuthService, error) {
	// Validate BFF configuration
	if err := opts.ValidateBFFAuthOptions(); err != nil {
		return nil, fmt.Errorf("invalid BFF configuration: %w", err)
	}

	// Initialize session store for BFF
	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.Options = &sessions.Options{
		Domain:   opts.SessionDomain,
		MaxAge:   opts.SessionMaxAge,
		HttpOnly: true,
		Secure:   opts.SessionSecure,
		SameSite: http.SameSiteLaxMode, // Default for BFF
	}

	// Initialize BFF services
	sessionService := NewSessionService(sessionStore)
	jwtExchangeService := NewJWTExchangeService(opts.JWTSecret, sessionService, opts.JWTExpiry)
	bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, opts.SIDCookieName)

	// Initialize OAuth service if configuration is provided
	var oauthService OAuthService
	if opts.OAuth != nil {
		// Use the session store from OAuth config if provided, otherwise use the default one
		if opts.OAuth.SessionStore == nil {
			opts.OAuth.SessionStore = sessionStore
		}
		oauthService = NewOAuthService(opts.OAuth)
	}

	// For BFF, we don't initialize the traditional JWT middleware
	// since BFF handles JWT exchange internally
	return &AuthService{
		middleware:         nil, // BFF doesn't use traditional JWT middleware
		sessionStore:       sessionStore,
		oauthService:       oauthService,
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		bffMiddleware:      bffMiddleware,
	}, nil
}

// Wrapper functions for the middleware and session store
func (as *AuthService) MiddlewareFunc() gin.HandlerFunc {
	if as.middleware == nil {
		return nil
	}
	return as.middleware.MiddlewareFunc()
}

func (as *AuthService) LoginHandler() gin.HandlerFunc {
	if as.middleware == nil {
		return nil
	}
	return as.middleware.LoginHandler()
}

func (as *AuthService) LogoutHandler() gin.HandlerFunc {
	if as.middleware == nil {
		return nil
	}
	return as.middleware.LogoutHandler()
}

func (as *AuthService) RefreshHandler() gin.HandlerFunc {
	if as.middleware == nil {
		return nil
	}
	return as.middleware.RefreshHandler()
}

func (as *AuthService) GetSessionStore() sessions.Store {
	return as.sessionStore
}

func (as *AuthService) GetOAuthService() OAuthService {
	return as.oauthService
}

// GetSessionService returns the session service
func (as *AuthService) GetSessionService() SessionService {
	return as.sessionService
}

// GetJWTExchangeService returns the JWT exchange service
func (as *AuthService) GetJWTExchangeService() SessionExchangeService {
	return as.jwtExchangeService
}

// GetBFFAuthMiddleware returns the BFF auth middleware
func (as *AuthService) GetBFFAuthMiddleware() BFFAuthMiddleware {
	return as.bffMiddleware
}

// parseSameSite helper function (moved from utils to keep it internal)
func parseSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "Lax":
		return http.SameSiteLaxMode
	case "Strict":
		return http.SameSiteStrictMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
} 