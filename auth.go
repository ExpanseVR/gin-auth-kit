// Package auth provides authentication and authorization functionality
//
// Public API:
//   - NewAuthService() - Main entry point, use this in your application
//   - AuthService - Primary service for all authentication operations
//   - AuthMiddleware interface - For implementing custom auth methods
//
// Private implementation details:
//   - JWTMiddleware, newJWTMiddleware() - Internal JWT implementation
//   - Helper functions - Internal utilities
//
// Usage:
//
//	authService, err := auth.NewAuthService(opts, userRepo, logger)
//	router.POST("/login", authService.LoginHandler())
//	router.Use(authService.MiddlewareFunc())
package auth

import (
	"github.com/ExpanseVR/gin-auth-kit/utils"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

// AuthMiddleware defines the interface for authentication middleware implementations
type AuthMiddleware interface {
	LoginHandler() gin.HandlerFunc
	MiddlewareFunc() gin.HandlerFunc
	RefreshHandler() gin.HandlerFunc
	LogoutHandler() gin.HandlerFunc
}

// AuthService provides centralized authentication functionality
// It can orchestrate multiple authentication methods (JWT, API keys, OAuth, etc.)
// This is the main public interface - use this instead of individual middleware types
type AuthService struct {
	// Primary authentication method (currently JWT)
	primaryAuth AuthMiddleware

	// Session store for OAuth and other stateful authentication
	sessionStore *sessions.CookieStore

	// User repository for data operations
	userRepo UserRepository

	// Logger for auth operations
	logger Logger

	// Configuration
	config *AuthOptions
}

// NewAuthService creates a new authentication service
// This is the main entry point - use this instead of creating middleware directly
func NewAuthService(opts *AuthOptions, userRepo UserRepository, logger Logger) (*AuthService, error) {
	// Initialize JWT middleware as primary auth method
	jwtMiddleware, err := newJWTMiddleware(opts, userRepo, logger)
	if err != nil {
		return nil, err
	}

	// Initialize secure session store for OAuth
	sessionStore := sessions.NewCookieStore([]byte(opts.SessionSecret))
	sessionStore.MaxAge(opts.SessionMaxAge)
	sessionStore.Options.Domain = opts.SessionDomain
	sessionStore.Options.Secure = opts.SessionSecure
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.SameSite = utils.ParseSameSite(opts.SessionSameSite)

	return &AuthService{
		primaryAuth:  jwtMiddleware,
		sessionStore: sessionStore,
		userRepo:     userRepo,
		logger:       logger,
		config:       opts,
	}, nil
}

// Primary authentication methods (delegates to JWT middleware)
func (s *AuthService) LoginHandler() gin.HandlerFunc {
	return s.primaryAuth.LoginHandler()
}

func (s *AuthService) MiddlewareFunc() gin.HandlerFunc {
	return s.primaryAuth.MiddlewareFunc()
}

func (s *AuthService) RefreshHandler() gin.HandlerFunc {
	return s.primaryAuth.RefreshHandler()
}

func (s *AuthService) LogoutHandler() gin.HandlerFunc {
	return s.primaryAuth.LogoutHandler()
}

// OAuth and session-based authentication methods
func (s *AuthService) SessionStore() *sessions.CookieStore {
	return s.sessionStore
}

// Future methods for additional auth types:
// func (s *AuthService) APIKeyMiddleware() gin.HandlerFunc { ... }
// func (s *AuthService) OAuthCallbackHandler(provider string) gin.HandlerFunc { ... }
// func (s *AuthService) SetPrimaryAuth(auth AuthMiddleware) { s.primaryAuth = auth }
