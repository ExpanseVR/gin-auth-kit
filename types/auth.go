package types

import (
	"errors"
	"fmt"
	"time"
)

// AuthOptions represents configuration for traditional authentication
type AuthOptions struct {
	// JWT Configuration
	JWTSecret           string
	JWTRealm           string
	TokenExpireTime    time.Duration
	RefreshExpireTime  time.Duration
	IdentityKey        string

	// Session Configuration  
	SessionSecret string
	SessionMaxAge int
	SessionDomain string
	SessionSecure bool
	SessionSameSite string

	// OAuth Configuration
	OAuth *OAuthConfig

	// Callback Functions
	FindUserByEmail FindUserByEmailFunc
	FindUserByID    FindUserByIDFunc
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

	// Validate OAuth configuration if provided
	if opts.OAuth != nil {
		if err := opts.OAuth.ValidateOAuthConfig(); err != nil {
			return fmt.Errorf("OAuth configuration invalid: %w", err)
		}
	}

	return nil
}
