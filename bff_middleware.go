package auth

import (
	"errors"
	"net/http"

	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/gin-gonic/gin"
)

type BFFAuthMiddleware struct {
	sessionService     types.SessionService
	jwtExchangeService *JWTExchangeService
	sidCookieName      string
}

func NewBFFAuthMiddleware(sessionService types.SessionService, jwtExchangeService *JWTExchangeService, sidCookieName string) *BFFAuthMiddleware {
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

func (auth *BFFAuthMiddleware) validateSessionFromCookie(ctx *gin.Context) (string, types.UserInfo, error) {
	sid := auth.getSIDFromCookie(ctx)
	if sid == "" {
		return "", types.UserInfo{}, errors.New("no session cookie")
	}

	userInfo, err := auth.sessionService.ValidateSession(sid)
	return sid, userInfo, err
}

func (auth *BFFAuthMiddleware) RequireSession() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(ctx)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			ctx.Abort()
			return
		}

		ctx.Set("user", userInfo)
		ctx.Set("sid", sid)
		ctx.Next()
	}
}

func (auth *BFFAuthMiddleware) RequireValidSession() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(ctx)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Session required"})
			ctx.Abort()
			return
		}

		jwt, err := auth.jwtExchangeService.ExchangeSessionForJWT(sid)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
			ctx.Abort()
			return
		}

		ctx.Set("user", userInfo)
		ctx.Set("sid", sid)
		ctx.Set("jwt", jwt)
		ctx.Next()
	}
}

func (auth *BFFAuthMiddleware) OptionalSession() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sid, userInfo, err := auth.validateSessionFromCookie(ctx)
		if err != nil {
			ctx.Next()
			return
		}

		ctx.Set("user", userInfo)
		ctx.Set("sid", sid)
		ctx.Next()
	}
}

func (auth *BFFAuthMiddleware) getSIDFromCookie(ctx *gin.Context) string {
	cookie, err := ctx.Cookie(auth.sidCookieName)
	if err != nil {
		return ""
	}

	return cookie
}
