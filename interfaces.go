package auth

import (
	"time"
)

// UserInfo represents user data returned by callback functions
type UserInfo struct {
	ID           uint   `json:"id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"` // Never expose password hash in JSON
}

// UserFinder callback function types
type FindUserByEmailFunc func(email string) (UserInfo, error)
type FindUserByIDFunc func(id uint) (UserInfo, error)

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

	// Security Settings
	BcryptCost int

	// Callback Functions
	FindUserByEmail FindUserByEmailFunc
	FindUserByID    FindUserByIDFunc
} 