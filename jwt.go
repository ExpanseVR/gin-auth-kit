package auth

import (
	"fmt"
	"time"

	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/ExpanseVR/gin-auth-kit/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

type JWTOptions struct {
	Realm             string
	Key               []byte
	Timeout           time.Duration
	MaxRefresh        time.Duration
	IdentityKey       string
	FindUserByEmail   types.FindUserByEmailFunc
	FindUserByID      types.FindUserByIDFunc
	SessionSecure     bool
	SessionDomain     string
	SessionSameSite   string
}

type JWTMiddleware struct {
	*jwt.GinJWTMiddleware
}

func NewJWTMiddleware(opts *JWTOptions) (*JWTMiddleware, error) {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           opts.Realm,
		Key:             opts.Key,
		Timeout:         opts.Timeout,
		MaxRefresh:      opts.MaxRefresh,
		IdentityKey:     opts.IdentityKey,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler(&AuthOptions{
			FindUserByEmail: opts.FindUserByEmail,
			FindUserByID:    opts.FindUserByID,
		}),
		Authenticator:   Authenticator(&AuthOptions{
			FindUserByEmail: opts.FindUserByEmail,
			FindUserByID:    opts.FindUserByID,
		}),
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
		return nil, fmt.Errorf("failed to create JWT middleware: %w", err)
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