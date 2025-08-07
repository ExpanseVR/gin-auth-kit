package types

import (
	"time"

	"github.com/gin-gonic/gin"
)

// UserFinder callback function types
type FindUserByEmailFunc func(email string) (UserInfo, error)
type FindUserByIDFunc func(id uint) (UserInfo, error)

// AuthMiddleware defines the interface that all auth middleware must implement
// This allows for different auth strategies (JWT, session, etc.)
type AuthMiddleware interface {
	MiddlewareFunc() gin.HandlerFunc
	LoginHandler() gin.HandlerFunc
	LogoutHandler() gin.HandlerFunc
	RefreshHandler() gin.HandlerFunc
}

// SessionService defines the interface for session management
type SessionService interface {
	CreateSession(user UserInfo, expiry time.Duration) (string, error)
	GetSession(sid string) (UserInfo, error)
	DeleteSession(sid string) error
	ValidateSession(sid string) (UserInfo, error)
}
