package auth

import (
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"

	"github.com/ExpanseVR/gin-auth-kit/utils"
)

// PayloadFunc extracts user information into JWT claims
// Called when: User successfully logs in - creates JWT payload from user data
func PayloadFunc(data interface{}) jwt.MapClaims {
	if user, ok := data.(*UserInfo); ok {
		return jwt.MapClaims{
			"user_id": user.ID,
			"email":   user.Email,
			"role":    user.Role,
		}
	}
	return jwt.MapClaims{}
}

// IdentityHandler retrieves user identity from JWT claims
// Called when: JWT token is validated - reconstructs user from token claims
func IdentityHandler(opts *AuthOptions) func(c *gin.Context) interface{} {
	return func(c *gin.Context) interface{} {
		claims := jwt.ExtractClaims(c)
		
		userIDFloat, exists := claims["user_id"]
		if !exists {
			return nil
		}
		
		// Convert to uint (JWT stores numbers as float64)
		userID, ok := userIDFloat.(float64)
		if !ok {
			return nil
		}

		// Use callback to get user data
		user, err := opts.FindUserByID(uint(userID))
		if err != nil {
			return nil 
		}

		return &user
	}
}

// Authenticator validates login credentials
// Called when: User attempts to login - validates email/password combination
func Authenticator(opts *AuthOptions) func(c *gin.Context) (interface{}, error) {
	return func(c *gin.Context) (interface{}, error) {
		var loginRequest struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			return nil, jwt.ErrMissingLoginValues
		}

		// Use callback to get user by email
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
func Authorizator(data interface{}, c *gin.Context) bool {
	if user, ok := data.(*UserInfo); ok {
		// Basic authorization - all authenticated users allowed
		// Override this function for role-based access control
		return user.ID > 0
	}
	return false
}

// Unauthorized handles cases where authentication/authorization fails
// Called when: JWT token is invalid, expired, or user lacks permissions
func Unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
} 