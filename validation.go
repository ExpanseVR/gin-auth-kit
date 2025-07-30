package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ValidateBFFAuthOptions validates BFF authentication configuration
func (opts *BFFAuthOptions) ValidateBFFAuthOptions() error {
	if opts == nil {
		return errors.New("BFFAuthOptions cannot be nil")
	}

	if opts.SessionSecret == "" {
		return errors.New("SessionSecret is required")
	}

	if opts.SessionMaxAge <= 0 {
		return errors.New("SessionMaxAge must be positive")
	}

	if opts.JWTSecret == "" {
		return errors.New("JWTSecret is required")
	}

	if opts.JWTExpiry <= 0 {
		return errors.New("JWTExpiry must be positive")
	}

	if opts.SessionService == nil {
		return errors.New("SessionService is required")
	}

	if opts.SIDCookieName == "" {
		opts.SIDCookieName = "sid" // Set default
	}

	if opts.SIDCookiePath == "" {
		opts.SIDCookiePath = "/" // Set default
	}

	if opts.FindUserByEmail == nil {
		return errors.New("FindUserByEmail callback is required")
	}

	if opts.FindUserByID == nil {
		return errors.New("FindUserByID callback is required")
	}

	if opts.OAuth != nil {
		if err := opts.OAuth.ValidateOAuthConfig(); err != nil {
			return fmt.Errorf("OAuth configuration invalid: %w", err)
		}
	}

	return nil
}

// ValidateOAuthConfig validates OAuth configuration
func (config *OAuthConfig) ValidateOAuthConfig() error {
	if config == nil {
		return errors.New("OAuthConfig cannot be nil")
	}

	if len(config.Providers) == 0 {
		return errors.New("at least one OAuth provider is required")
	}

	for name, provider := range config.Providers {
		if err := provider.ValidateOAuthProvider(); err != nil {
			return fmt.Errorf("provider %s: %w", name, err)
		}
	}

	if config.BaseURL == "" {
		return errors.New("BaseURL is required")
	}

	if config.SuccessURL == "" {
		return errors.New("SuccessURL is required")
	}

	if config.FailureURL == "" {
		return errors.New("FailureURL is required")
	}

	return nil
}

// ValidateOAuthProvider validates individual OAuth provider configuration
func (provider *OAuthProvider) ValidateOAuthProvider() error {
	if provider.ClientID == "" {
		return errors.New("ClientID is required")
	}

	if provider.ClientSecret == "" {
		return errors.New("ClientSecret is required")
	}

	if provider.RedirectURL == "" {
		return errors.New("RedirectURL is required")
	}

	if _, err := url.Parse(provider.RedirectURL); err != nil {
		return fmt.Errorf("RedirectURL must be a valid URL: %w", err)
	}

	// Validate scopes (optional but if provided, should not be empty)
	if len(provider.Scopes) > 0 {
		for i, scope := range provider.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("scope %d cannot be empty", i)
			}
		}
	}

	return nil
}

// ValidateAuthOptions validates traditional authentication configuration
func (opts *AuthOptions) ValidateAuthOptions() error {
	if opts == nil {
		return errors.New("AuthOptions cannot be nil")
	}

	if opts.SessionSecret == "" {
		return errors.New("SessionSecret is required")
	}

	if opts.SessionMaxAge <= 0 {
		return errors.New("SessionMaxAge must be positive")
	}

	// JWT validation (only if JWT is being used)
	if opts.JWTSecret != "" {
		if opts.TokenExpireTime <= 0 {
			return errors.New("TokenExpireTime must be positive")
		}

		if opts.RefreshExpireTime <= 0 {
			return errors.New("RefreshExpireTime must be positive")
		}

		if opts.IdentityKey == "" {
			opts.IdentityKey = "user_id" // Set default
		}

		if opts.FindUserByEmail == nil {
			return errors.New("FindUserByEmail callback is required")
		}

		if opts.FindUserByID == nil {
			return errors.New("FindUserByID callback is required")
		}
	}

	// Set defaults for optional session fields
	if opts.JWTRealm == "" {
		opts.JWTRealm = "gin-auth-kit" // Set default
	}

	if opts.SessionSameSite == "" {
		opts.SessionSameSite = "Lax" // Set default
	}

	if opts.BcryptCost <= 0 {
		opts.BcryptCost = 12 // Set default
	}

	// Validate OAuth configuration if provided
	if opts.OAuth != nil {
		if err := opts.OAuth.ValidateOAuthConfig(); err != nil {
			return fmt.Errorf("OAuth configuration invalid: %w", err)
		}
	}

	return nil
} 