package auth

import (
	"github.com/ExpanseVR/gin-auth-kit/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// JWT middleware callback functions for gin-jwt
func PayloadFunc(data interface{}) jwt.MapClaims {
	if v, ok := data.(User); ok {
		return jwt.MapClaims{
			"user_id": v.GetID(),
			"email":   v.GetEmail(),
			"role":    v.GetRole(),
		}
	}
	return jwt.MapClaims{}
}

// IdentityHandler retrieves user from token claims
func IdentityHandler(userRepo UserRepository, logger Logger) func(c *gin.Context) interface{} {
	return func(c *gin.Context) interface{} {
		claims := jwt.ExtractClaims(c)

		// Add type assertion safety
		userIDClaim, ok := claims["user_id"]
		if !ok {
			logger.Error().Msg("Missing user_id in JWT claims")
			return nil
		}

		userID, ok := userIDClaim.(float64)
		if !ok {
			logger.Error().Msg("Invalid user_id type in JWT claims")
			return nil
		}

		user, err := userRepo.FindByID(uint(userID))
		if err != nil {
			logger.Warn().Uint("user_id", uint(userID)).Msg("User not found")
			return nil
		}

		return user
	}
}

// Authenticator validates login credentials
func Authenticator(userRepo UserRepository, logger Logger) func(c *gin.Context) (interface{}, error) {
	return func(c *gin.Context) (interface{}, error) {
		var loginRequest struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBind(&loginRequest); err != nil {
			return "", jwt.ErrMissingLoginValues
		}

		user, err := userRepo.FindByEmail(loginRequest.Email)
		if err != nil {
			logger.Error().Err(err).Str("email", loginRequest.Email).Msg("Failed to find user by email")
			return nil, jwt.ErrFailedAuthentication
		}

		if err := utils.VerifyPassword(user.GetPasswordHash(), loginRequest.Password); err != nil {
			logger.Warn().Str("email", loginRequest.Email).Msg("Failed password verification")
			return nil, jwt.ErrFailedAuthentication
		}

		return user, nil
	}
}

// Authorizator checks user permissions/roles
func Authorizator(data interface{}, c *gin.Context) bool {
	if user, ok := data.(User); ok {
		// Basic authorization - user exists and is valid
		// Role-based checks will be implemented in RBAC step
		return user.GetID() > 0
	}
	return false
}

// Unauthorized handles authentication failures
func Unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"error":   "Unauthorized",
		"message": message,
		"code":    code,
	})
}
