package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// bffAuthMiddleware implements the BFFAuthMiddleware interface
type bffAuthMiddleware struct {
	sessionService SessionService
	jwtExchangeService SessionExchangeService
	sidCookieName string
}

// NewBFFAuthMiddleware creates a new BFF auth middleware instance
func NewBFFAuthMiddleware(sessionService SessionService, jwtExchangeService SessionExchangeService, sidCookieName string) BFFAuthMiddleware {
	return &bffAuthMiddleware{
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		sidCookieName:      sidCookieName,
	}
}

// RequireSession middleware that requires a valid session
func (b *bffAuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get SID from cookie
		sid := getSIDFromCookie(c, b.sidCookieName)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session required",
				"code":  "SESSION_REQUIRED",
			})
			c.Abort()
			return
		}

		// Validate session
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid session",
				"code":  "INVALID_SESSION",
			})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

// RequireValidSession middleware that requires a valid session and exchanges it for JWT
func (b *bffAuthMiddleware) RequireValidSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get SID from cookie
		sid := getSIDFromCookie(c, b.sidCookieName)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session required",
				"code":  "SESSION_REQUIRED",
			})
			c.Abort()
			return
		}

		// Exchange session for JWT
		jwt, err := b.jwtExchangeService.ExchangeSessionForJWT(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session exchange failed",
				"code":  "SESSION_EXCHANGE_FAILED",
			})
			c.Abort()
			return
		}

		// Validate session to get user info
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid session",
				"code":  "INVALID_SESSION",
			})
			c.Abort()
			return
		}

		// Set user info and JWT in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Set("jwt", jwt)
		c.Next()
	}
}

// OptionalSession middleware that optionally validates a session if present
func (b *bffAuthMiddleware) OptionalSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get SID from cookie
		sid := getSIDFromCookie(c, b.sidCookieName)
		if sid == "" {
			// No session present, continue without authentication
			c.Next()
			return
		}

		// Try to validate session
		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			// Invalid session, continue without authentication
			c.Next()
			return
		}

		// Valid session found, set user info in context
		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

// getSIDFromCookie extracts the SID from the request cookies
func getSIDFromCookie(c *gin.Context, cookieName string) string {
	if cookieName == "" {
		cookieName = "sid" // Default cookie name
	}

	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return ""
	}

	return cookie
} 