package auth

import (
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/ExpanseVR/gin-auth-kit/utils"
)

// JWTOptions contains configuration for JWT middleware
type JWTOptions struct {
	Realm             string
	Key               []byte
	Timeout           time.Duration
	MaxRefresh        time.Duration
	IdentityKey       string
	FindUserByEmail   FindUserByEmailFunc
	FindUserByID      FindUserByIDFunc
	SessionSecure     bool
	SessionDomain     string
	SessionSameSite   string
}

// JWTMiddleware implements AuthMiddleware using JWT tokens
type JWTMiddleware struct {
	*jwt.GinJWTMiddleware
}

// Verify JWTMiddleware implements AuthMiddleware interface
var _ AuthMiddleware = (*JWTMiddleware)(nil)

// NewJWTMiddleware creates a new JWT middleware with the given options
func NewJWTMiddleware(opts *JWTOptions) *JWTMiddleware {
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
		// In the new architecture, we'll panic on JWT middleware creation errors
		// since this indicates a configuration problem that should be caught early
		panic(err)
	}

	return &JWTMiddleware{
		GinJWTMiddleware: authMiddleware,
	}
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