package auth

import (
	"testing"
	"time"

	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockFindUserByEmail(email string) (types.UserInfo, error) {
	if email == "test@example.com" {
		return types.UserInfo{
			ID:    1,
			Email: email,
			Role:  "user",
		}, nil
	}
	return types.UserInfo{}, ErrUserNotFound
}

func mockFindUserByID(id uint) (types.UserInfo, error) {
	if id == 1 {
		return types.UserInfo{
			ID:    id,
			Email: "test@example.com",
			Role:  "user",
		}, nil
	}
	return types.UserInfo{}, ErrUserNotFound
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
		FindUserByEmail:   mockFindUserByEmail,
		FindUserByID:      mockFindUserByID,
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)

	// Should have JWT service
	assert.NotNil(t, authService.JWT)
	assert.NotNil(t, authService.JWT.Middleware)

	// Should not have BFF or OAuth services
	assert.Nil(t, authService.BFF)
	assert.Nil(t, authService.OAuth)
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
			BaseURL:    "http://localhost:8080",
			SuccessURL: "/dashboard",
			FailureURL: "/login",
		},
	}

	authService, err := NewAuthService(opts)
	require.NoError(t, err)

	// Should have JWT and OAuth services
	assert.NotNil(t, authService.JWT)
	assert.NotNil(t, authService.OAuth)

	// Should not have BFF service
	assert.Nil(t, authService.BFF)
}

func TestBackwardCompatibility(t *testing.T) {
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

	// JWT-only configuration should still work
	assert.NotNil(t, authService.JWT)
	assert.Nil(t, authService.BFF)
	assert.Nil(t, authService.OAuth)
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
		// Should now fail validation - FindUserByEmail is required for JWT
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByEmail callback is required")
		assert.Nil(t, authService)
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
		// Should now fail validation - FindUserByID is required for JWT
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByID callback is required")
		assert.Nil(t, authService)
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

func TestAuthOptionsValidation(t *testing.T) {
	t.Run("Valid_AuthOptions", func(t *testing.T) {
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

		err := opts.ValidateAuthOptions()
		assert.NoError(t, err)
	})

	t.Run("Nil_AuthOptions", func(t *testing.T) {
		var opts *AuthOptions = nil
		err := opts.ValidateAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AuthOptions cannot be nil")
	})

	t.Run("Missing_SessionSecret", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:       "test-secret",
			SessionMaxAge:   86400,
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionSecret is required")
	})

	t.Run("Invalid_SessionMaxAge", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:       "test-secret",
			SessionSecret:   "session-secret",
			SessionMaxAge:   -1,
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionMaxAge must be positive")
	})

	t.Run("OAuth_Only_Configuration", func(t *testing.T) {
		opts := &AuthOptions{
			SessionSecret: "session-secret",
			SessionMaxAge: 86400,
			OAuth: &OAuthConfig{
				Providers: map[string]OAuthProvider{
					"google": {
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
						RedirectURL:  "https://example.com/callback",
						Scopes:       []string{"email", "profile"},
					},
				},
				BaseURL:    "https://example.com",
				SuccessURL: "/dashboard",
				FailureURL: "/login",
			},
		}

		err := opts.ValidateAuthOptions()
		assert.NoError(t, err)
		// Should set defaults
		assert.Equal(t, "gin-auth-kit", opts.JWTRealm)
		assert.Equal(t, "Lax", opts.SessionSameSite)
	})

	t.Run("JWT_Missing_TokenExpireTime", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:       "test-secret",
			SessionSecret:   "session-secret",
			SessionMaxAge:   86400,
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TokenExpireTime must be positive")
	})

	t.Run("Default_Values_Set", func(t *testing.T) {
		opts := &AuthOptions{
			JWTSecret:         "test-secret",
			TokenExpireTime:   time.Hour,
			RefreshExpireTime: time.Hour * 24,
			SessionSecret:     "session-secret",
			SessionMaxAge:     86400,
			FindUserByEmail:   mockFindUserByEmail,
			FindUserByID:      mockFindUserByID,
		}

		err := opts.ValidateAuthOptions()
		assert.NoError(t, err)
		
		// Check that defaults were set
		assert.Equal(t, "user_id", opts.IdentityKey)
		assert.Equal(t, "gin-auth-kit", opts.JWTRealm)
		assert.Equal(t, "Lax", opts.SessionSameSite)
	})
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
		types.SessionService
	}{
		SessionService: &mockSessionServiceImpl{},
	}

	opts := &BFFAuthOptions{
		SessionSecret:   "test-session-secret",
		SessionMaxAge:   86400,
		JWTSecret:       "test-jwt-secret",
		JWTExpiry:       time.Hour,
		SIDCookieName:   "sid",
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
		types.SessionService
	}{
		SessionService: &mockSessionServiceImpl{},
	}

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