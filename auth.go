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
	MiddlewareFunc() gin.HandlerFunc // Function for protecting routes
	LoginHandler() gin.HandlerFunc // Returns the Gin handler for user login
	LogoutHandler() gin.HandlerFunc // Returns the Gin handler for user logout
	RefreshHandler() gin.HandlerFunc // Returns the Gin handler for token refresh
}

type AuthService struct {
	middleware   AuthMiddleware
	sessionStore sessions.Store
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

	return &AuthService{
		middleware:   jwtMiddleware,
		sessionStore: sessionStore,
	}, nil
}

// Wrapper functions for the middleware and session store
func (as *AuthService) MiddlewareFunc() gin.HandlerFunc {
	return as.middleware.MiddlewareFunc()
}

func (as *AuthService) LoginHandler() gin.HandlerFunc {
	return as.middleware.LoginHandler()
}

func (as *AuthService) LogoutHandler() gin.HandlerFunc {
	return as.middleware.LogoutHandler()
}

func (as *AuthService) RefreshHandler() gin.HandlerFunc {
	return as.middleware.RefreshHandler()
}

func (as *AuthService) GetSessionStore() sessions.Store {
	return as.sessionStore
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