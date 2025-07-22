package auth

import (
	"time"
)

// User represents any user type that can be authenticated
type User interface {
	GetID() uint
	GetEmail() string
	GetRole() string
	GetPasswordHash() string
}

// UserRepository handles user data operations
type UserRepository interface {
	FindByEmail(email string) (User, error)
	FindByID(id uint) (User, error)
}

// Logger provides logging functionality for the auth plugin
type Logger interface {
	Error() LogEvent
	Warn() LogEvent
	Debug() LogEvent
}

// LogEvent represents a log event that can be chained
type LogEvent interface {
	Err(err error) LogEvent
	Msg(msg string)
	Str(key, val string) LogEvent
	Uint(key string, val uint) LogEvent
}

// AuthOptions contains all configuration needed by the auth plugin
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
} 