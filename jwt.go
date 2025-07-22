package auth

import (
	"time"

	"github.com/ExpanseVR/gin-auth-kit/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// JWTMiddleware wraps the gin-jwt middleware and implements AuthMiddleware interface
type JWTMiddleware struct {
	*jwt.GinJWTMiddleware
}

// Ensure JWTMiddleware implements AuthMiddleware interface
var _ AuthMiddleware = (*JWTMiddleware)(nil)

// newJWTMiddleware creates a new JWT middleware instance (private - use AuthService instead)
func newJWTMiddleware(opts *AuthOptions, userRepo UserRepository, logger Logger) (*JWTMiddleware, error) {
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           opts.JWTRealm,
		Key:             []byte(opts.JWTSecret),
		Timeout:         opts.TokenExpireTime,
		MaxRefresh:      opts.RefreshExpireTime,
		IdentityKey:     opts.IdentityKey,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler(userRepo, logger),
		Authenticator:   Authenticator(userRepo, logger),
		Authorizator:    Authorizator,
		Unauthorized:    Unauthorized,
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,

		// Enable automatic token refresh
		SendCookie:     true,
		SecureCookie:   opts.SessionSecure,
		CookieHTTPOnly: true,
		CookieDomain:   opts.SessionDomain,
		CookieName:     "jwt",
		CookieSameSite: utils.ParseSameSite(opts.SessionSameSite),
	})

	if err != nil {
		logger.Error().Err(err).Msg("Failed to create JWT middleware")
		return nil, err
	}

	// Initialize middleware
	err = authMiddleware.MiddlewareInit()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize JWT middleware")
		return nil, err
	}

	return &JWTMiddleware{authMiddleware}, nil
}

// LoginHandler returns the login handler (implements AuthMiddleware)
func (mw *JWTMiddleware) LoginHandler() gin.HandlerFunc {
	return mw.GinJWTMiddleware.LoginHandler
}

// MiddlewareFunc returns the JWT middleware function (implements AuthMiddleware)
func (mw *JWTMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return mw.GinJWTMiddleware.MiddlewareFunc()
}

// RefreshHandler returns the refresh token handler (implements AuthMiddleware)
func (mw *JWTMiddleware) RefreshHandler() gin.HandlerFunc {
	return mw.GinJWTMiddleware.RefreshHandler
}

// LogoutHandler handles token logout/invalidation (implements AuthMiddleware)
func (mw *JWTMiddleware) LogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// With stateless JWT, we primarily rely on token expiration
		// Clear the cookie if it exists
		c.SetCookie("jwt", "", -1, "/", "", false, true)

		c.JSON(200, gin.H{
			"message": "Successfully logged out",
		})
	}
}
