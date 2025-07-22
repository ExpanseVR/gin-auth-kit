# gin-auth-kit

Complete JWT authentication toolkit for Gin web framework with clean, callback-based design.

[![Go Reference](https://pkg.go.dev/badge/github.com/ExpanseVR/gin-auth-kit.svg)](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **Simple Setup** - Just provide two callback functions, no complex adapters needed
- **Hybrid Token Support** - Automatic cookie + header + query parameter JWT handling
- **Database Agnostic** - Works with any database through simple callback functions
- **Production Ready** - Proper error handling, security defaults, bcrypt password hashing
- **Zero Dependencies** - No coupling to GORM, Zerolog, or any specific libraries
- **Easy Testing** - Mock callback functions instead of complex interfaces

## Installation

```bash
go get github.com/ExpanseVR/gin-auth-kit@v1.0.1
```

## Quick Start

### 1. Define Your User Model

```go
type User struct {
    ID           uint   `json:"id"`
    Email        string `json:"email"`
    PasswordHash string `json:"-"`
    Role         string `json:"role"`
}
```

### 2. Setup Authentication

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

func main() {
    opts := &auth.AuthOptions{
        JWTSecret:         "your-secret-key",
        JWTRealm:         "your-app",
        TokenExpireTime:  time.Hour,
        RefreshExpireTime: 7 * 24 * time.Hour,
        IdentityKey:      "user_id",
        SessionSecret:    "your-session-secret",
        SessionMaxAge:    86400,
        BcryptCost:       12,

        FindUserByEmail: func(email string) (auth.UserInfo, error) {
            user, err := db.GetUserByEmail(email)
            if err != nil {
                return auth.UserInfo{}, err
            }
            return auth.UserInfo{
                ID:           user.ID,
                Email:        user.Email,
                Role:         user.Role,
                PasswordHash: user.PasswordHash,
            }, nil
        },

        FindUserByID: func(id uint) (auth.UserInfo, error) {
            user, err := db.GetUserByID(id)
            if err != nil {
                return auth.UserInfo{}, err
            }
            return auth.UserInfo{
                ID:           user.ID,
                Email:        user.Email,
                Role:         user.Role,
                PasswordHash: user.PasswordHash,
            }, nil
        },
    }

    authService, err := auth.NewAuthService(opts)
    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }

    router := gin.Default()

    // Auth endpoints
    authGroup := router.Group("/api/auth")
    {
        authGroup.POST("/login", authService.LoginHandler())
        authGroup.POST("/refresh", authService.RefreshHandler())
        authGroup.POST("/logout", authService.LogoutHandler())
    }

    // Protected routes
    protected := router.Group("/api/protected")
    protected.Use(authService.MiddlewareFunc())
    {
        protected.GET("/profile", getProfile)
        protected.POST("/update", updateProfile)
    }

    router.Run(":8080")
}
```

## Token Handling

gin-auth-kit supports multiple token delivery methods simultaneously:

### Cookie-Based (Web Apps)

```javascript
fetch("/api/protected/profile", {
  credentials: "include", // Cookies sent automatically
});
```

### Header-Based (APIs/SPAs)

```javascript
const token = localStorage.getItem("jwt_token");
fetch("/api/protected/profile", {
  headers: { Authorization: `Bearer ${token}` },
});
```

### Query Parameter (Special Cases)

```javascript
window.open(`/api/export?token=${token}`);
```

**Token Lookup Priority**: Header → Cookie → Query Parameter

## Configuration

### AuthOptions

See [Go Reference](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit#AuthOptions) for complete configuration options.

### UserInfo Struct

```go
type UserInfo struct {
    ID           uint   `json:"id"`
    Email        string `json:"email"`
    Role         string `json:"role"`
    PasswordHash string `json:"-"`
}
```

## API Endpoints

### POST `/login`

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**

```json
{
  "code": 200,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expire": "2024-01-01T12:00:00Z"
}
```

### POST `/refresh`

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### POST `/logout`

Invalidates the current session.

## Testing

```go
func TestAuth(t *testing.T) {
    mockUsers := map[string]auth.UserInfo{
        "test@example.com": {
            ID: 1, Email: "test@example.com",
            Role: "user", PasswordHash: "hashedpw",
        },
    }

    opts := &auth.AuthOptions{
        JWTSecret: "test-secret",
        TokenExpireTime: time.Hour,

        FindUserByEmail: func(email string) (auth.UserInfo, error) {
            if user, exists := mockUsers[email]; exists {
                return user, nil
            }
            return auth.UserInfo{}, errors.New("user not found")
        },

        FindUserByID: func(id uint) (auth.UserInfo, error) {
            for _, user := range mockUsers {
                if user.ID == id {
                    return user, nil
                }
            }
            return auth.UserInfo{}, errors.New("user not found")
        },
    }

    authService, err := auth.NewAuthService(opts)
    assert.NoError(t, err)
}
```

## Password Utilities

```go
import "github.com/ExpanseVR/gin-auth-kit/utils"

// Hash a password
hashedPassword, err := utils.HashPassword("password123", 12)

// Verify a password
err := utils.VerifyPassword(hashedPassword, "password123")
```

## Migration from v1.0.0

See [CHANGELOG.md](CHANGELOG.md) for migration guide from interface-based to callback-based design.

## Roadmap

- OAuth 2.0 providers (Google, GitHub, Apple)
- Role-Based Access Control (RBAC)
- API Key authentication
- Rate limiting middleware
- Multi-factor authentication (MFA)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Acknowledgments

- Built on top of gin-jwt middleware
- Inspired by clean architecture principles
- Designed for production use in modern Go applications
