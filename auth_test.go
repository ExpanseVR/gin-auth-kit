package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions
func mockFindUserByEmail(email string) (UserInfo, error) {
	if email == "test@example.com" {
		return UserInfo{
			ID:    1,
			Email: "test@example.com",
			Role:  "user",
		}, nil
	}
	return UserInfo{}, ErrUserNotFound
}

func mockFindUserByID(id uint) (UserInfo, error) {
	if id == 1 {
		return UserInfo{
			ID:    1,
			Email: "test@example.com",
			Role:  "user",
		}, nil
	}
	return UserInfo{}, ErrUserNotFound
}

func TestJWTOnlyConfiguration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:         "test-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		SessionDomain:     "localhost",
		SessionSecure:     false,
		SessionSameSite:   "Lax",
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// JWT service should be available
	assert.NotNil(t, authService.JWT)
	assert.NotNil(t, authService.JWT.Middleware)

	// BFF services should not be available
	assert.Nil(t, authService.BFF)

	// OAuth should not be configured
	assert.Nil(t, authService.OAuth)

	// Session store should be available
	assert.NotNil(t, authService.SessionStore)
}

func TestOAuthConfiguration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:         "test-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		SessionDomain:     "localhost",
		SessionSecure:     false,
		SessionSameSite:   "Lax",
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
		OAuth: &OAuthConfig{
			Providers: map[string]OAuthProvider{
				"google": {
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
					Scopes:       []string{"email", "profile"},
				},
			},
			BaseURL:         "http://localhost:8080",
			SuccessURL:      "/dashboard",
			FailureURL:      "/login?error=oauth_failed",
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		},
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// OAuth should be configured
	assert.NotNil(t, authService.OAuth)

	// Session store should be available
	assert.NotNil(t, authService.SessionStore)
}

func TestBackwardCompatibility(t *testing.T) {
	// Test that JWT-only configurations still work
	opts := &AuthOptions{
		JWTSecret:         "test-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Should have JWT functionality
	assert.NotNil(t, authService.JWT)
	assert.NotNil(t, authService.JWT.Middleware.MiddlewareFunc())
	assert.NotNil(t, authService.JWT.Middleware.LoginHandler())
	assert.NotNil(t, authService.JWT.Middleware.LogoutHandler())
	assert.NotNil(t, authService.JWT.Middleware.RefreshHandler())
}

func TestErrorHandling(t *testing.T) {
	t.Run("Missing_FindUserByEmail", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:         "test-secret",
			JWTRealm:         "test",
			TokenExpireTime:   time.Hour,
			RefreshExpireTime: time.Hour * 24,
			IdentityKey:       "id",
			SessionSecret:     "session-secret",
			SessionMaxAge:     86400,
			FindUserByID:      mockFindUserByID,
		}

		authService, err := NewAuthService(opts)
		// Should still create service - validation happens at JWT middleware level
		assert.NoError(t, err)
		assert.NotNil(t, authService)
	})

	t.Run("Missing_FindUserByID", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:         "test-secret",
			JWTRealm:         "test",
			TokenExpireTime:   time.Hour,
			RefreshExpireTime: time.Hour * 24,
			IdentityKey:       "id",
			SessionSecret:     "session-secret",
			SessionMaxAge:     86400,
			FindUserByEmail:   mockFindUserByEmail,
		}

		authService, err := NewAuthService(opts)
		// Should still create service - validation happens at JWT middleware level
		assert.NoError(t, err)
		assert.NotNil(t, authService)
	})

	t.Run("Valid_configuration", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:         "test-secret",
			JWTRealm:         "test",
			TokenExpireTime:   time.Hour,
			RefreshExpireTime: time.Hour * 24,
			IdentityKey:       "id",
			SessionSecret:     "session-secret",
			SessionMaxAge:     86400,
			FindUserByEmail:   mockFindUserByEmail,
			FindUserByID:      mockFindUserByID,
		}

		authService, err := NewAuthService(opts)
		assert.NoError(t, err)
		assert.NotNil(t, authService)
	})
}

func TestSessionStoreIntegration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:         "test-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)

	sessionStore := authService.SessionStore
	assert.NotNil(t, sessionStore)

	// Test session store functionality
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	session, err := sessionStore.New(req, "test-session")
	assert.NoError(t, err)
	assert.NotNil(t, session)

	session.Values["test"] = "value"
	err = sessionStore.Save(req, w, session)
	assert.NoError(t, err)
}

func TestGinIntegration(t *testing.T) {
	opts := &AuthOptions{
		JWTSecret:         "test-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)

	// Test that middleware can be used with Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Should be able to use JWT middleware
	r.Use(authService.JWT.Middleware.MiddlewareFunc())
	r.POST("/login", authService.JWT.Middleware.LoginHandler())
	r.POST("/logout", authService.JWT.Middleware.LogoutHandler())
	r.POST("/refresh", authService.JWT.Middleware.RefreshHandler())

	assert.NotNil(t, r)
}

func TestBFFConfiguration(t *testing.T) {
	// Create a simple mock SessionService for testing
	mockSessionService := &struct {
		SessionService
	}{}

	opts := &BFFAuthOptions{
		SessionSecret:   "test-session-secret",
		SessionMaxAge:   86400,
		SessionDomain:   "localhost",
		SessionSecure:   false,
		JWTSecret:       "test-jwt-secret",
		JWTExpiry:       10 * time.Minute,
		SIDCookieName:   "sid",
		SIDCookiePath:   "/",
		SessionService:  mockSessionService,
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:    mockFindUserByID,
	}

	authService, err := NewBFFAuthService(opts)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// BFF services should be available
	assert.NotNil(t, authService.BFF)
	assert.NotNil(t, authService.BFF.Sessions)
	assert.NotNil(t, authService.BFF.Exchange)
	assert.NotNil(t, authService.BFF.Middleware)

	// JWT service should not be available in BFF mode
	assert.Nil(t, authService.JWT)

	// Session store should be available
	assert.NotNil(t, authService.SessionStore)
}

func TestBFFAndJWTCoexistence(t *testing.T) {
	// Test traditional JWT service (no BFF services)
	jwtOpts := &AuthOptions{
		JWTSecret:         "test-jwt-secret",
		JWTRealm:         "test",
		TokenExpireTime:   time.Hour,
		RefreshExpireTime: time.Hour * 24,
		IdentityKey:       "id",
		SessionSecret:     "session-secret",
		SessionMaxAge:     86400,
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	jwtService, err := NewAuthService(jwtOpts)
	require.NoError(t, err)
	require.NotNil(t, jwtService)

	// JWT service should have JWT functionality
	assert.NotNil(t, jwtService.JWT)
	assert.NotNil(t, jwtService.JWT.Middleware)

	// BFF services not available in JWT mode
	assert.Nil(t, jwtService.BFF)

	// Test BFF service (with OAuth)
	mockSessionService := &struct {
		SessionService
	}{}

	bffOpts := &BFFAuthOptions{
		SessionSecret:   "test-session-secret",
		SessionMaxAge:   86400,
		SessionDomain:   "localhost",
		SessionSecure:   false,
		JWTSecret:       "test-jwt-secret",
		JWTExpiry:       10 * time.Minute,
		SIDCookieName:   "sid",
		SIDCookiePath:   "/",
		SessionService:  mockSessionService,
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:    mockFindUserByID,
		OAuth: &OAuthConfig{
			Providers: map[string]OAuthProvider{
				"google": {
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
					RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
					Scopes:       []string{"email", "profile"},
				},
			},
			BaseURL:         "http://localhost:8080",
			SuccessURL:      "/dashboard",
			FailureURL:      "/login?error=oauth_failed",
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		},
	}

	bffService, err := NewBFFAuthService(bffOpts)
	require.NoError(t, err)
	require.NotNil(t, bffService)

	// BFF service should have BFF functionality
	assert.Nil(t, bffService.JWT)
	assert.NotNil(t, bffService.BFF)
	assert.NotNil(t, bffService.BFF.Sessions)
	assert.NotNil(t, bffService.BFF.Exchange)
	assert.NotNil(t, bffService.BFF.Middleware)
	assert.NotNil(t, bffService.OAuth)
} 