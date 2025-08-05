package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type BFFAuthMiddleware struct {
	sessionService     SessionService
	jwtExchangeService *JWTExchangeService
	sidCookieName      string
}

func NewBFFAuthMiddleware(sessionService SessionService, jwtExchangeService *JWTExchangeService, sidCookieName string) *BFFAuthMiddleware {
	// Ensure sidCookieName has a default value if empty
	if sidCookieName == "" {
		sidCookieName = "sid"
	}
	
	return &BFFAuthMiddleware{
		sessionService:     sessionService,
		jwtExchangeService: jwtExchangeService,
		sidCookieName:      sidCookieName,
	}
}

func (auth *BFFAuthMiddleware) validateSessionFromCookie(c *gin.Context) (string, UserInfo, error) {
	sid := auth.getSIDFromCookie(c)
	if sid == "" {
		return "", UserInfo{}, errors.New("no session cookie")
	}
	
	userInfo, err := auth.sessionService.ValidateSession(sid)
	return sid, userInfo, err
}

func (auth *BFFAuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

func (auth *BFFAuthMiddleware) RequireValidSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			c.Abort()
			return
		}

		jwt, err := auth.jwtExchangeService.ExchangeSessionForJWT(sid)
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

func (auth *BFFAuthMiddleware) OptionalSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(c)
		if err != nil {
			c.Next()
			return
		}

		c.Set("user", userInfo)
		c.Set("sid", sid)
		c.Next()
	}
}

func (auth *BFFAuthMiddleware) getSIDFromCookie(ctx *gin.Context) string {
	cookie, err := ctx.Cookie(auth.sidCookieName)
	if err != nil {
		return ""
	}

	return cookie
} 