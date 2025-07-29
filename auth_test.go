package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock user finder functions for testing
func mockFindUserByEmail(email string) (UserInfo, error) {
	if email == "test@example.com" {
		return UserInfo{
			ID:    1,
			Email: "test@example.com",
			Role:  "customer",
		}, nil
	}
	return UserInfo{}, ErrUserNotFound
}

func mockFindUserByID(id uint) (UserInfo, error) {
	if id == 1 {
		return UserInfo{
			ID:    1,
			Email: "test@example.com",
			Role:  "customer",
		}, nil
	}
	return UserInfo{}, ErrUserNotFound
}

// TestJWTOnlyConfiguration tests that JWT-only configuration still works
func TestJWTOnlyConfiguration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:          "test-secret-key",
		JWTRealm:          "test-realm",
		TokenExpireTime:    time.Hour,
		RefreshExpireTime:  time.Hour * 24,
		IdentityKey:        "user",
		SessionSecret:      "session-secret",
		SessionMaxAge:      3600,
		SessionDomain:      "",
		SessionSecure:      false,
		SessionSameSite:    "Lax",
		BcryptCost:         10,
		FindUserByEmail:    mockFindUserByEmail,
		FindUserByID:       mockFindUserByID,
		OAuth:              nil, // JWT-only configuration
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Test that OAuth service is nil for JWT-only config
	assert.Nil(t, authService.GetOAuthService())

	// Test that session store is available
	sessionStore := authService.GetSessionStore()
	assert.NotNil(t, sessionStore)
	assert.IsType(t, &sessions.CookieStore{}, sessionStore)
}

// TestOAuthConfiguration tests that OAuth configuration works alongside JWT
func TestOAuthConfiguration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:          "test-secret-key",
		JWTRealm:          "test-realm",
		TokenExpireTime:    time.Hour,
		RefreshExpireTime:  time.Hour * 24,
		IdentityKey:        "user",
		SessionSecret:      "session-secret",
		SessionMaxAge:      3600,
		SessionDomain:      "",
		SessionSecure:      false,
		SessionSameSite:    "Lax",
		BcryptCost:         10,
		FindUserByEmail:    mockFindUserByEmail,
		FindUserByID:       mockFindUserByID,
		OAuth: &OAuthConfig{
			Providers: map[string]OAuthProvider{
				"google": {
					ClientID:     "test-google-client-id",
					ClientSecret: "test-google-secret",
					RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
					Scopes:       []string{"email", "profile"},
				},
			},
			BaseURL:    "http://localhost:8080",
			SuccessURL: "/dashboard",
			FailureURL: "/login",
		},
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Test that OAuth service is available
	oauthService := authService.GetOAuthService()
	assert.NotNil(t, oauthService)

	// Test that session store is shared between JWT and OAuth
	sessionStore := authService.GetSessionStore()
	assert.NotNil(t, sessionStore)
	assert.IsType(t, &sessions.CookieStore{}, sessionStore)
}

// TestBackwardCompatibility tests that existing JWT functionality still works
func TestBackwardCompatibility(t *testing.T) {
	// Test with minimal JWT configuration (like existing code might use)
	opts := &AuthOptions{
		JWTSecret:       "test-secret-key",
		SessionSecret:   "session-secret",
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:    mockFindUserByID,
		// OAuth: nil (default)
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Verify all JWT middleware functions are available
	assert.NotNil(t, authService.MiddlewareFunc())
	assert.NotNil(t, authService.LoginHandler())
	assert.NotNil(t, authService.LogoutHandler())
	assert.NotNil(t, authService.RefreshHandler())
}

// TestErrorHandling tests error scenarios for invalid configurations
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		opts        *AuthOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "Missing FindUserByEmail",
			opts: &AuthOptions{
				JWTSecret: "test-secret",
				// FindUserByEmail: nil
				FindUserByID: mockFindUserByID,
			},
			expectError: true,
			errorMsg:    "FindUserByEmail callback is required",
		},
		{
			name: "Missing FindUserByID",
			opts: &AuthOptions{
				JWTSecret:       "test-secret",
				FindUserByEmail: mockFindUserByEmail,
				// FindUserByID: nil
			},
			expectError: true,
			errorMsg:    "FindUserByID callback is required",
		},
		{
			name: "Valid configuration",
			opts: &AuthOptions{
				JWTSecret:       "test-secret",
				SessionSecret:   "session-secret",
				FindUserByEmail: mockFindUserByEmail,
				FindUserByID:    mockFindUserByID,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, err := NewAuthService(tt.opts)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, authService)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authService)
			}
		})
	}
}

// TestSessionStoreIntegration tests that session store works for both JWT and OAuth
func TestSessionStoreIntegration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:       "test-secret-key",
		SessionSecret:   "session-secret",
		SessionMaxAge:   3600,
		SessionDomain:   "",
		SessionSecure:   false,
		SessionSameSite: "Lax",
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:    mockFindUserByID,
		OAuth: &OAuthConfig{
			Providers: map[string]OAuthProvider{
				"google": {
					ClientID:     "test-client-id",
					ClientSecret: "test-secret",
					RedirectURL:  "http://localhost:8080/callback",
				},
			},
		},
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)

	sessionStore := authService.GetSessionStore()
	require.NotNil(t, sessionStore)

	// Test that session store can create sessions with a proper request
	req, err := http.NewRequest("GET", "/test", nil)
	require.NoError(t, err)
	
	session, err := sessionStore.New(req, "test-session")
	require.NoError(t, err)
	assert.NotNil(t, session)
}

// TestGinIntegration tests that the auth service integrates properly with Gin
func TestGinIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	opts := &AuthOptions{
		JWTSecret:          "test-secret-key",
		JWTRealm:          "test-realm",
		TokenExpireTime:    time.Hour,
		RefreshExpireTime:  time.Hour * 24,
		IdentityKey:        "user",
		SessionSecret:      "session-secret",
		SessionMaxAge:      3600,
		SessionDomain:      "",
		SessionSecure:      false,
		SessionSameSite:    "Lax",
		BcryptCost:         10,
		FindUserByEmail:    mockFindUserByEmail,
		FindUserByID:       mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Test that middleware functions are available
	assert.NotNil(t, authService.MiddlewareFunc())
	assert.NotNil(t, authService.LoginHandler())
	assert.NotNil(t, authService.LogoutHandler())
	assert.NotNil(t, authService.RefreshHandler())
}

// TestBFFConfiguration tests that BFF configuration works
func TestBFFConfiguration(t *testing.T) {
	opts := &BFFAuthOptions{
		SessionSecret: "test-session-secret",
		SessionMaxAge: 86400,
		JWTSecret:     "test-jwt-secret",
		JWTExpiry:     10 * time.Minute,
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:   mockFindUserByID,
	}

	authService, err := NewBFFAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Test that BFF services are available
	assert.NotNil(t, authService.GetSessionService())
	assert.NotNil(t, authService.GetJWTExchangeService())
	assert.NotNil(t, authService.GetBFFAuthMiddleware())

	// Test that traditional middleware is nil for BFF-only config
	assert.Nil(t, authService.MiddlewareFunc())

	// Test that session store is available
	sessionStore := authService.GetSessionStore()
	assert.NotNil(t, sessionStore)
	assert.IsType(t, &sessions.CookieStore{}, sessionStore)
}

// TestBFFAndJWTCoexistence tests that BFF and JWT can coexist in the same service
func TestBFFAndJWTCoexistence(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:          "test-secret-key",
		JWTRealm:          "test-realm",
		TokenExpireTime:    time.Hour,
		RefreshExpireTime:  time.Hour * 24,
		IdentityKey:        "user",
		SessionSecret:      "session-secret",
		SessionMaxAge:      3600,
		SessionDomain:      "",
		SessionSecure:      false,
		SessionSameSite:    "Lax",
		BcryptCost:         10,
		FindUserByEmail:    mockFindUserByEmail,
		FindUserByID:       mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Test that both traditional JWT middleware and BFF services are available
	assert.NotNil(t, authService.MiddlewareFunc())
	assert.NotNil(t, authService.GetSessionService())
	assert.NotNil(t, authService.GetJWTExchangeService())
	assert.NotNil(t, authService.GetBFFAuthMiddleware())

	// Test that OAuth service is nil when not configured
	assert.Nil(t, authService.GetOAuthService())
} 