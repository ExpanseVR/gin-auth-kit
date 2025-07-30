package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type BFFAuthMiddleware struct {
	sessionService     SessionService
	jwtExchangeService *JWTExchangeService
	sidCookieName      string
}

func NewBFFAuthMiddleware(sessionService SessionService, jwtExchangeService *JWTExchangeService, sidCookieName string) *BFFAuthMiddleware {
	return &BFFAuthMiddleware{
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		sidCookieName:      sidCookieName,
	}
}

func (b *BFFAuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

func (b *BFFAuthMiddleware) RequireValidSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		jwt, err := b.jwtExchangeService.ExchangeSessionForJWT(sid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
			c.Abort()
			return
		}

		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Set("jwt", jwt)
		c.Next()
	}
}

func (b *BFFAuthMiddleware) OptionalSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := b.getSIDFromCookie(c)
		if sid == "" {
			c.Next()
			return
		}

		userInfo, err := b.sessionService.ValidateSession(sid)
		if err != nil {
			c.Next()
			return
		}

		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

func (b *BFFAuthMiddleware) getSIDFromCookie(c *gin.Context) string {
	if b.sidCookieName == "" {
		b.sidCookieName = "sid"
	}

	cookie, err := c.Cookie(b.sidCookieName)
	if err != nil {
		return ""
	}

	return cookie
} 