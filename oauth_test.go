package auth

import (
	"testing"

	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuthProviderValidation tests OAuth provider configuration validation
func TestOAuthProviderValidation(t *testing.T) {
	tests := []struct {
		name        string
		provider    OAuthProvider
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid Google Provider",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
				Scopes:       []string{"email", "profile"},
			},
			expectError: false,
		},
		{
			name: "Missing ClientID",
			provider: OAuthProvider{
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
			},
			expectError: true,
			errorMsg:    "ClientID is required",
		},
		{
			name: "Missing ClientSecret",
			provider: OAuthProvider{
				ClientID:    "test-client-id",
				RedirectURL: "http://localhost:8080/auth/callback",
			},
			expectError: true,
			errorMsg:    "ClientSecret is required",
		},
		{
			name: "Missing RedirectURL",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
			expectError: true,
			errorMsg:    "RedirectURL is required",
		},
		{
			name: "Valid URL with Query Parameters",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback?param=value",
				Scopes:       []string{"email", "profile"},
			},
			expectError: false,
		},
		{
			name: "Empty Scope",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
				Scopes:       []string{"email", ""}, // Empty scope
			},
			expectError: true,
			errorMsg:    "scope 1 cannot be empty",
		},
		{
			name: "Whitespace Scope",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
				Scopes:       []string{"email", "   "}, // Whitespace scope
			},
			expectError: true,
			errorMsg:    "scope 1 cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProvider("test-provider", tt.provider)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCreateGothProvider tests Goth provider creation from OAuth configuration
func TestCreateGothProvider(t *testing.T) {
	tests := []struct {
		name         string
		provider     OAuthProvider
		providerName string
		expectError  bool
		errorMsg     string
	}{
		{
			name: "Valid Google Provider",
			provider: OAuthProvider{
				ClientID:     "test-google-client-id",
				ClientSecret: "test-google-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
			providerName: "google",
			expectError:  false,
		},
		{
			name: "Valid GitHub Provider",
			provider: OAuthProvider{
				ClientID:     "test-github-client-id",
				ClientSecret: "test-github-secret",
				RedirectURL:  "http://localhost:8080/auth/github/callback",
				Scopes:       []string{"user:email"},
			},
			providerName: "github",
			expectError:  false,
		},
		{
			name: "Valid Facebook Provider",
			provider: OAuthProvider{
				ClientID:     "test-facebook-client-id",
				ClientSecret: "test-facebook-secret",
				RedirectURL:  "http://localhost:8080/auth/facebook/callback",
				Scopes:       []string{"email"},
			},
			providerName: "facebook",
			expectError:  false,
		},
		{
			name: "Unsupported Provider",
			provider: OAuthProvider{
				ClientID:     "test-client-id",
				ClientSecret: "test-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
			},
			providerName: "unsupported",
			expectError:  true,
			errorMsg:     "unsupported oauth provider",
		},
		{
			name: "Invalid Provider Config",
			provider: OAuthProvider{
				ClientID:     "", // Missing ClientID
				ClientSecret: "test-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
			},
			providerName: "google",
			expectError:  true,
			errorMsg:     "ClientID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gothProvider, err := createGothProvider(tt.providerName, tt.provider)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, gothProvider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, gothProvider)

				// Verify it's the correct provider type
				switch tt.providerName {
				case "google":
					assert.IsType(t, &google.Provider{}, gothProvider)
				case "github":
					// GitHub provider type check
					assert.NotNil(t, gothProvider)
				case "facebook":
					// Facebook provider type check
					assert.NotNil(t, gothProvider)
				}
			}
		})
	}
}

// TestOAuthServiceInitialization tests OAuth service creation and initialization
func TestOAuthServiceInitialization(t *testing.T) {
	tests := []struct {
		name        string
		config      *OAuthConfig
		expectError bool
	}{
		{
			name: "Valid OAuth Config",
			config: &OAuthConfig{
				Providers: map[string]OAuthProvider{
					"google": {
						ClientID:     "test-google-client-id",
						ClientSecret: "test-google-secret",
						RedirectURL:  "http://localhost:8080/auth/google/callback",
						Scopes:       []string{"email", "profile"},
					},
				},
				BaseURL:    "http://localhost:8080",
				SuccessURL: "/dashboard",
				FailureURL: "/login",
			},
			expectError: false,
		},
		{
			name: "Empty Providers",
			config: &OAuthConfig{
				Providers:  map[string]OAuthProvider{},
				BaseURL:    "http://localhost:8080",
				SuccessURL: "/dashboard",
				FailureURL: "/login",
			},
			expectError: false, // Should not error, just no providers
		},
		{
			name:        "Nil Config",
			config:      nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oauthService := NewOAuthService(tt.config)

			if tt.expectError {
				assert.Nil(t, oauthService)
			} else {
				assert.NotNil(t, oauthService)

				// Test that the service is properly initialized
				assert.NotNil(t, oauthService.Providers)
			}
		})
	}
}

// TestProviderManagement tests provider registration and retrieval
func TestProviderManagement(t *testing.T) {
	config := &OAuthConfig{
		Providers: map[string]OAuthProvider{
			"google": {
				ClientID:     "test-google-client-id",
				ClientSecret: "test-google-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
		},
		BaseURL:    "http://localhost:8080",
		SuccessURL: "/dashboard",
		FailureURL: "/login",
	}

	oauthService := NewOAuthService(config)
	require.NotNil(t, oauthService)

	// Test GetProvider for existing provider
	provider, err := oauthService.GetProvider("google")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.IsType(t, &google.Provider{}, provider)

	// Test GetProvider for non-existing provider
	provider, err = oauthService.GetProvider("nonexistent")
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Equal(t, ErrProviderNotFound, err)
}

// TestOAuthServiceInterface tests that all interface methods are implemented
func TestOAuthServiceInterface(t *testing.T) {
	config := &OAuthConfig{
		Providers: map[string]OAuthProvider{
			"google": {
				ClientID:     "test-google-client-id",
				ClientSecret: "test-google-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
		},
		BaseURL:    "http://localhost:8080",
		SuccessURL: "/dashboard",
		FailureURL: "/login",
	}

	oauthService := NewOAuthService(config)
	require.NotNil(t, oauthService)

	// Test that all interface methods return valid handlers/functions
	beginAuthHandler := oauthService.BeginAuthHandler()
	assert.NotNil(t, beginAuthHandler)

	completeAuthHandler := oauthService.CompleteAuthHandler()
	assert.NotNil(t, completeAuthHandler)

	// Test user mapping (now implemented)
	gothUser := goth.User{
		UserID: "123",
		Email:  "test@example.com",
		Name:   "Test User",
	}

	userInfo, err := oauthService.MapGothUserToUserInfo(gothUser)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", userInfo.Email)
	assert.Equal(t, "user", userInfo.Role)
	assert.Equal(t, uint(123), userInfo.ID)
}

// TestOAuthErrorHandling tests OAuth-specific error scenarios
func TestOAuthErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		config      *OAuthConfig
		expectError bool
	}{
		{
			name: "Invalid Provider Config",
			config: &OAuthConfig{
				Providers: map[string]OAuthProvider{
					"google": {
						ClientID:     "", // Invalid: missing ClientID
						ClientSecret: "test-secret",
						RedirectURL:  "http://localhost:8080/auth/callback",
					},
				},
			},
			expectError: false, // Should not error, just skip invalid provider
		},
		{
			name: "Unsupported Provider",
			config: &OAuthConfig{
				Providers: map[string]OAuthProvider{
					"unsupported": {
						ClientID:     "test-client-id",
						ClientSecret: "test-secret",
						RedirectURL:  "http://localhost:8080/auth/callback",
					},
				},
			},
			expectError: false, // Should not error, just skip unsupported provider
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oauthService := NewOAuthService(tt.config)

			// Should not error, but may have no providers
			assert.NotNil(t, oauthService)

			// Try to get a provider that should not exist
			provider, err := oauthService.GetProvider("google")
			assert.Error(t, err)
			assert.Nil(t, provider)
			assert.Equal(t, ErrProviderNotFound, err)
		})
	}
}

// TestUserMapping tests the MapGothUserToUserInfo functionality
func TestUserMapping(t *testing.T) {
	config := &OAuthConfig{
		Providers: map[string]OAuthProvider{
			"google": {
				ClientID:     "test-google-client-id",
				ClientSecret: "test-google-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
		},
		BaseURL:         "http://localhost:8080",
		SuccessURL:      "/dashboard",
		FailureURL:      "/login",
		FindUserByEmail: mockFindUserByEmail,
		FindUserByID:    mockFindUserByID,
	}

	oauthService := NewOAuthService(config)
	require.NotNil(t, oauthService)

	tests := []struct {
		name         string
		gothUser     goth.User
		expectError  bool
		errorMsg     string
		expectedUser types.UserInfo
	}{
		{
			name: "Valid Goth User with ID",
			gothUser: goth.User{
				UserID: "123",
				Email:  "test@example.com",
				Name:   "Test User",
			},
			expectError: false,
			expectedUser: types.UserInfo{
				ID:    1, // Mock function returns existing user ID
				Email: "test@example.com",
				Role:  "user",
			},
		},
		{
			name: "Valid Goth User without ID",
			gothUser: goth.User{
				Email: "newuser@example.com",
				Name:  "New User",
			},
			expectError: false,
			expectedUser: types.UserInfo{
				ID:    0, // No ID for new users
				Email: "newuser@example.com",
				Role:  "user",
			},
		},
		{
			name: "Goth User with invalid ID",
			gothUser: goth.User{
				UserID: "invalid-id",
				Email:  "test@example.com",
				Name:   "Test User",
			},
			expectError: false,
			expectedUser: types.UserInfo{
				ID:    1, // Mock function returns existing user ID
				Email: "test@example.com",
				Role:  "user",
			},
		},
		{
			name: "Missing Email",
			gothUser: goth.User{
				UserID: "123",
				Name:   "Test User",
			},
			expectError: true,
			errorMsg:    "email is required",
		},
		{
			name: "Empty Email",
			gothUser: goth.User{
				UserID: "123",
				Email:  "",
				Name:   "Test User",
			},
			expectError: true,
			errorMsg:    "email is required",
		},
		{
			name: "Existing User by Email",
			gothUser: goth.User{
				UserID: "999", // Different ID, but email matches existing user
				Email:  "test@example.com",
				Name:   "Test User",
			},
			expectError: false,
			expectedUser: types.UserInfo{
				ID:    1, // Mock function returns existing user ID
				Email: "test@example.com",
				Role:  "user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userInfo, err := oauthService.MapGothUserToUserInfo(tt.gothUser)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUser.Email, userInfo.Email)
				assert.Equal(t, tt.expectedUser.Role, userInfo.Role)
				assert.Equal(t, tt.expectedUser.ID, userInfo.ID)
			}
		})
	}
}

// TestUserMappingWithoutCallbacks tests user mapping when callbacks are not provided
func TestUserMappingWithoutCallbacks(t *testing.T) {
	config := &OAuthConfig{
		Providers: map[string]OAuthProvider{
			"google": {
				ClientID:     "test-google-client-id",
				ClientSecret: "test-google-secret",
				RedirectURL:  "http://localhost:8080/auth/google/callback",
				Scopes:       []string{"email", "profile"},
			},
		},
		BaseURL:    "http://localhost:8080",
		SuccessURL: "/dashboard",
		FailureURL: "/login",
		// No callbacks provided
	}

	oauthService := NewOAuthService(config)
	require.NotNil(t, oauthService)

	gothUser := goth.User{
		UserID: "123",
		Email:  "test@example.com",
		Name:   "Test User",
	}

	userInfo, err := oauthService.MapGothUserToUserInfo(gothUser)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", userInfo.Email)
	assert.Equal(t, "user", userInfo.Role)
	assert.Equal(t, uint(123), userInfo.ID)
}

func TestProviderRegistrationWithoutOverwriting(t *testing.T) {
	// Create an empty OAuth service
	service := &OAuthService{
		Providers: make(map[string]goth.Provider),
	}

	// Create test providers
	googleProvider := google.New("google-client-id", "google-secret", "http://localhost:8080/auth/google/callback")
	githubProvider := github.New("github-client-id", "github-secret", "http://localhost:8080/auth/github/callback")

	// Register first provider
	service.RegisterProvider("google", googleProvider)

	// Verify first provider is registered
	provider, err := service.GetProvider("google")
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	assert.IsType(t, &google.Provider{}, provider)

	// Register second provider
	service.RegisterProvider("github", githubProvider)

	// Verify both providers are still available
	googleProvider2, err := service.GetProvider("google")
	assert.NoError(t, err)
	assert.NotNil(t, googleProvider2)
	assert.IsType(t, &google.Provider{}, googleProvider2)

	githubProvider2, err := service.GetProvider("github")
	assert.NoError(t, err)
	assert.NotNil(t, githubProvider2)
	assert.IsType(t, &github.Provider{}, githubProvider2)

	// Verify the service has both providers in its map
	assert.Equal(t, 2, len(service.Providers))
	assert.Contains(t, service.Providers, "google")
	assert.Contains(t, service.Providers, "github")
}
