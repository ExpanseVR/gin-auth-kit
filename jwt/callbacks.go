package gak_jwt

import (
	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/ExpanseVR/gin-auth-kit/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
)

// PayloadFunc extracts user information into JWT claims
// Called when: User successfully logs in - creates JWT payload from user data
func PayloadFunc(data any) jwt.MapClaims {
	if user, ok := data.(*types.UserInfo); ok {
		claims := jwt.MapClaims{
			"user_id":    user.ID,
			"email":      user.Email,
			"role":       user.Role,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		}

		// Add custom fields to JWT claims
		if user.CustomFields != nil {
			for key, value := range user.CustomFields {
				claims["custom_"+key] = value
			}
		}

		return claims
	}
	return jwt.MapClaims{}
}

// IdentityHandler retrieves user identity from JWT claims
// Called when: JWT token is validated - reconstructs user from token claims
func IdentityHandler(opts *types.AuthOptions) func(ctx *gin.Context) any {
	return func(ctx *gin.Context) any {
		claims := jwt.ExtractClaims(ctx)

		userIDFloat, exists := claims["user_id"]
		if !exists {
			return nil
		}

		userID, ok := userIDFloat.(float64)
		if !ok {
			return nil
		}

		user, err := opts.FindUserByID(uint(userID))
		if err != nil {
			return nil
		}

		return &user
	}
}

// Authenticator validates login credentials
// Called when: User attempts to login - validates email/password combination
func Authenticator(opts *types.AuthOptions) func(ctx *gin.Context) (any, error) {
	return func(ctx *gin.Context) (any, error) {
		var loginRequest struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}

		if err := ctx.ShouldBindJSON(&loginRequest); err != nil {
			return nil, jwt.ErrMissingLoginValues
		}

		user, err := opts.FindUserByEmail(loginRequest.Email)
		if err != nil {
			return nil, jwt.ErrFailedAuthentication
		}

		if err := utils.VerifyPassword(user.PasswordHash, loginRequest.Password); err != nil {
			return nil, jwt.ErrFailedAuthentication
		}

		return &user, nil
	}
}

// Authorizator determines if authenticated user has access to resource
// Called when: Access to protected endpoint is requested - checks user permissions
func Authorizator(data any, ctx *gin.Context) bool {
	if user, ok := data.(*types.UserInfo); ok {
		return user.Role == "admin" || user.Role == "user"
	}
	return false
}

// Unauthorized handles cases where authentication/authorization fails
// Called when: JWT token is invalid, expired, or user lacks permissions
func Unauthorized(ctx *gin.Context, code int, message string) {
	ctx.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
}
