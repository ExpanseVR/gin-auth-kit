package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BFFAuthMiddleware provides BFF authentication middleware
type BFFAuthMiddleware struct {
	sessionService     SessionService
	jwtExchangeService *JWTExchangeService
	sidCookieName      string
}

// NewBFFAuthMiddleware creates a new BFF auth middleware instance
func NewBFFAuthMiddleware(sessionService SessionService, jwtExchangeService *JWTExchangeService, sidCookieName string) *BFFAuthMiddleware {
	return &BFFAuthMiddleware{
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		sidCookieName:      sidCookieName,
	}
}

// RequireSession middleware that requires a valid session
func (b *BFFAuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		// Validate session
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		// Store user info in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

// RequireValidSession middleware that requires a valid session and provides JWT
func (b *BFFAuthMiddleware) RequireValidSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		// Validate session
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		// Generate JWT for API calls
		jwt, err := b.jwtExchangeService.ExchangeSessionForJWT(sid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
			c.Abort()
			return
		}

		// Store user info and JWT in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Set("jwt", jwt)
		c.Next()
	}
}

// OptionalSession middleware that optionally validates session
func (b *BFFAuthMiddleware) OptionalSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			// No session, continue without user info
			c.Next()
			return
		}

		// Try to validate session
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			// Invalid session, continue without user info
			c.Next()
			return
		}

		// Store user info in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

// getSIDFromCookie extracts the SID from the request cookies
func (b *BFFAuthMiddleware) getSIDFromCookie(c *gin.Context) string {
	if b.sidCookieName == "" {
		b.sidCookieName = "sid" // Default cookie name
	}

	cookie, err := c.Cookie(b.sidCookieName)
	if err != nil {
		return ""
	}

	return cookie
} 