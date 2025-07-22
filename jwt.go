package auth

import (
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/ExpanseVR/gin-auth-kit/utils"
)

// JWTMiddleware implements AuthMiddleware using JWT tokens
type JWTMiddleware struct {
	*jwt.GinJWTMiddleware
}

// Verify JWTMiddleware implements AuthMiddleware interface
var _ AuthMiddleware = (*JWTMiddleware)(nil)

func newJWTMiddleware(opts *AuthOptions) (*JWTMiddleware, error) {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           opts.JWTRealm,
		Key:             []byte(opts.JWTSecret),
		Timeout:         opts.TokenExpireTime,
		MaxRefresh:      opts.RefreshExpireTime,
		IdentityKey:     opts.IdentityKey,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler(opts),
		Authenticator:   Authenticator(opts),
		Authorizator:    Authorizator,
		Unauthorized:    Unauthorized,
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",

		// Enable automatic token refresh
		SendCookie:     true,
		SecureCookie:   opts.SessionSecure,
		CookieHTTPOnly: true,
		CookieDomain:   opts.SessionDomain,
		CookieName:     "jwt",
		CookieSameSite: utils.ParseSameSite(opts.SessionSameSite),
	})

	if err != nil {
		return nil, err
	}

	return &JWTMiddleware{
		GinJWTMiddleware: authMiddleware,
	}, nil
}

func (j *JWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return j.GinJWTMiddleware.MiddlewareFunc()
}

func (j *JWTMiddleware) LoginHandler() gin.HandlerFunc {
	return j.GinJWTMiddleware.LoginHandler
}

func (j *JWTMiddleware) LogoutHandler() gin.HandlerFunc {
	return j.GinJWTMiddleware.LogoutHandler
}

func (j *JWTMiddleware) RefreshHandler() gin.HandlerFunc {
	return j.GinJWTMiddleware.RefreshHandler
} 