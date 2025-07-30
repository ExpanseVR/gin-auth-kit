# gin-auth-kit

Complete authentication toolkit for Gin web framework with JWT, OAuth, and BFF (Backend-for-Frontend) support. Clean, callback-based design with production-ready features.

[![Go Reference](https://pkg.go.dev/badge/github.com/ExpanseVR/gin-auth-kit.svg)](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **Multiple Authentication Methods** - JWT, OAuth 2.0, and BFF session-based authentication
- **OAuth Provider Support** - Google, GitHub, Facebook, and custom providers via Goth
- **BFF Architecture Support** - Session-based authentication with JWT exchange for microservices
- **Simple Setup** - Just provide callback functions, no complex adapters needed
- **Hybrid Token Support** - Automatic cookie + header + query parameter JWT handling
- **Database Agnostic** - Works with any database through simple callback functions
- **Production Ready** - Proper error handling, security defaults, bcrypt password hashing
- **Zero Dependencies** - No coupling to GORM, Zerolog, or any specific libraries
- **Easy Testing** - Mock callback functions instead of complex interfaces

## Installation

```bash
go get github.com/ExpanseVR/gin-auth-kit@latest
```

## Quick Start

### Traditional JWT + OAuth Setup

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

func main() {
    opts := &auth.AuthOptions{
        // JWT Configuration
        JWTSecret:         "your-jwt-secret",
        JWTRealm:         "your-app",
        TokenExpireTime:  time.Hour,
        RefreshExpireTime: 7 * 24 * time.Hour,
        IdentityKey:      "user_id",

        // Session Configuration
        SessionSecret:    "your-session-secret",
        SessionMaxAge:    86400,
        SessionDomain:    ".yourapp.com",
        SessionSecure:    true,
        SessionSameSite:  "Lax",
        BcryptCost:       12,

        // OAuth Configuration (Optional)
        OAuth: &auth.OAuthConfig{
            Providers: map[string]auth.OAuthProvider{
                "google": {
                    ClientID:     "your-google-client-id",
                    ClientSecret: "your-google-client-secret",
                    RedirectURL:  "https://yourapp.com/auth/oauth/google/callback",
                    Scopes:       []string{"email", "profile"},
                },
                "github": {
                    ClientID:     "your-github-client-id",
                    ClientSecret: "your-github-client-secret",
                    RedirectURL:  "https://yourapp.com/auth/oauth/github/callback",
                    Scopes:       []string{"user:email"},
                },
            },
            BaseURL:    "https://yourapp.com",
            SuccessURL: "/dashboard",
            FailureURL: "/login?error=oauth_failed",
        },

        // User callbacks
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

    // Traditional auth endpoints
    authGroup := router.Group("/api/auth")
    {
        authGroup.POST("/login", authService.LoginHandler())
        authGroup.POST("/refresh", authService.RefreshHandler())
        authGroup.POST("/logout", authService.LogoutHandler())
    }

    // OAuth endpoints (if configured)
    if authService.GetOAuthService() != nil {
        oauthGroup := router.Group("/auth/oauth")
        {
            oauthGroup.GET("/:provider", authService.GetOAuthService().BeginAuthHandler())
            oauthGroup.GET("/:provider/callback", authService.GetOAuthService().CompleteAuthHandler())
        }
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

### BFF (Backend-for-Frontend) Setup

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

func main() {
    opts := &auth.BFFAuthOptions{
        // Session configuration
        SessionSecret: "your-session-secret",
        SessionMaxAge: 86400 * 30, // 30 days
        SessionDomain: ".yourapp.com",
        SessionSecure: true,

        // JWT configuration
        JWTSecret: "your-jwt-secret",
        JWTExpiry: 10 * time.Minute,

        // Cookie configuration
        SIDCookieName: "sid",
        SIDCookiePath: "/",

        // User callbacks
        FindUserByEmail: func(email string) (auth.UserInfo, error) {
            user, err := db.GetUserByEmail(email)
            if err != nil {
                return auth.UserInfo{}, err
            }
            return auth.UserInfo{
                ID:    user.ID,
                Email: user.Email,
                Role:  user.Role,
            }, nil
        },

        FindUserByID: func(id uint) (auth.UserInfo, error) {
            user, err := db.GetUserByID(id)
            if err != nil {
                return auth.UserInfo{}, err
            }
            return auth.UserInfo{
                ID:    user.ID,
                Email: user.Email,
                Role:  user.Role,
            }, nil
        },

        // Optional OAuth configuration
        OAuth: &auth.OAuthConfig{
            Providers: map[string]auth.OAuthProvider{
                "google": {
                    ClientID:     "your-google-client-id",
                    ClientSecret: "your-google-client-secret",
                    RedirectURL:  "https://yourapp.com/auth/oauth/google/callback",
                    Scopes:       []string{"email", "profile"},
                },
            },
            BaseURL:    "https://yourapp.com",
            SuccessURL: "/dashboard",
            FailureURL: "/login?error=oauth_failed",
        },
    }

    bffService, err := auth.NewBFFAuthService(opts)
    if err != nil {
        log.Fatal("Failed to create BFF auth service:", err)
    }

    router := gin.Default()

    // BFF session endpoints
    bffGroup := router.Group("/api/bff")
    {
        // Session exchange for JWT (for microservice calls)
        bffGroup.POST("/exchange", func(c *gin.Context) {
            sid := auth.GetSIDCookie(c, "sid")
            if sid == "" {
                c.JSON(401, gin.H{"error": "No session"})
                return
            }

            jwt, err := bffService.GetJWTExchangeService().ExchangeSessionForJWT(sid)
            if err != nil {
                c.JSON(401, gin.H{"error": "Session exchange failed"})
                return
            }

            c.JSON(200, gin.H{"token": jwt})
        })

        // Session validation
        bffGroup.GET("/validate", bffService.GetBFFAuthMiddleware().RequireSession(), func(c *gin.Context) {
            user, _ := c.Get("user")
            c.JSON(200, gin.H{"user": user})
        })
    }

    // OAuth endpoints (if configured)
    if bffService.GetOAuthService() != nil {
        oauthGroup := router.Group("/auth/oauth")
        {
            oauthGroup.GET("/:provider", bffService.GetOAuthService().BeginAuthHandler())
            oauthGroup.GET("/:provider/callback", bffService.GetOAuthService().CompleteAuthHandler())
        }
    }

    // Protected routes using BFF middleware
    protected := router.Group("/api/protected")
    protected.Use(bffService.GetBFFAuthMiddleware().RequireSession())
    {
        protected.GET("/profile", getProfile)
        protected.POST("/update", updateProfile)
    }

    router.Run(":8080")
}
```

## Authentication Methods

### 1. Traditional JWT Authentication

- Email/password login with JWT tokens
- Automatic token refresh
- Multiple token delivery methods (header, cookie, query param)

### 2. OAuth 2.0 Authentication

- Support for Google, GitHub, Facebook, and custom providers
- Automatic user creation/lookup via callbacks
- Secure session state management

### 3. BFF (Backend-for-Frontend) Authentication

- Session-based authentication for web applications
- JWT exchange for microservice communication
- Secure SID cookies with HttpOnly flags
- Browser never sees JWT tokens

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

### AuthOptions (Traditional + OAuth)

See [Go Reference](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit#AuthOptions) for complete configuration options.

### BFFAuthOptions (BFF Architecture)

```go
type BFFAuthOptions struct {
    // Session configuration
    SessionSecret string
    SessionMaxAge int
    SessionDomain string
    SessionSecure bool

    // JWT configuration
    JWTSecret     string
    JWTExpiry     time.Duration

    // Cookie configuration
    SIDCookieName string
    SIDCookiePath string

    // User callbacks
    FindUserByEmail FindUserByEmailFunc
    FindUserByID    FindUserByIDFunc

    // OAuth configuration (optional)
    OAuth *OAuthConfig
}
```

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

### Traditional JWT Endpoints

#### POST `/api/auth/login`

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

#### POST `/api/auth/refresh`

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### POST `/api/auth/logout`

Invalidates the current session.

### OAuth Endpoints

#### GET `/auth/oauth/:provider`

Initiates OAuth flow for the specified provider (google, github, facebook, etc.).

#### GET `/auth/oauth/:provider/callback`

Handles OAuth callback and creates user session.

### BFF Endpoints

#### POST `/api/bff/exchange`

Exchanges session ID for JWT token (for microservice calls).

#### GET `/api/bff/validate`

Validates current session and returns user information.

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

### 🔄 In Progress

- [ ] Route integration helpers
- [ ] Advanced error handling integration
- [ ] Configuration examples and templates
- [ ] Integration tests and documentation

### 🚀 Planned (Future Versions)

- [ ] Redis session store optimization
- [ ] API Key authentication
- [ ] Rate limiting middleware
- [ ] Multi-factor authentication (MFA)
- [ ] Advanced RBAC (Role-Based Access Control)
- [ ] Audit logging and monitoring
- [ ] Performance optimization and caching

## Architecture Patterns

### Traditional JWT + OAuth

- Browser stores JWT tokens
- Direct API communication
- Suitable for SPAs and mobile apps

### BFF (Backend-for-Frontend)

- Browser stores only secure SID cookies
- Next.js/Server handles JWT exchange
- JWT tokens never exposed to browser
- Ideal for web applications with microservices

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
- OAuth support via Goth library
- Inspired by clean architecture principles
- Designed for production use in modern Go applications
