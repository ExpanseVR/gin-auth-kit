# gin-auth-kit

Complete authentication toolkit for Gin web framework with JWT, OAuth, and BFF (Backend-for-Frontend) support. Clean, callback-based design with production-ready features.

[![Go Reference](https://pkg.go.dev/badge/github.com/ExpanseVR/gin-auth-kit.svg)](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- **Multiple Authentication Methods** - JWT, OAuth 2.0, and BFF session-based authentication
- **OAuth Provider Support** - Google, GitHub, Facebook, and custom providers via Goth library
- **BFF Architecture Support** - Session-based authentication with JWT exchange for microservices
- **Interface-Driven Design** - SessionService interface for custom session storage implementations
- **Simple Setup** - Just provide callback functions, no complex adapters needed
- **Hybrid Token Support** - Automatic cookie + header + query parameter JWT handling
- **Database Agnostic** - Works with any database through simple callback functions
- **Production Ready** - Proper error handling, security defaults, bcrypt password hashing
- **Easy Testing** - Mock callback functions and interfaces instead of complex adapters
- **Secure Defaults** - HttpOnly cookies, SameSite protection, secure session management

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
        authGroup.POST("/login", authService.JWT.Middleware.LoginHandler())
        authGroup.POST("/refresh", authService.JWT.Middleware.RefreshHandler())
        authGroup.POST("/logout", authService.JWT.Middleware.LogoutHandler())
    }

    // OAuth endpoints (if configured)
    if authService.OAuth != nil {
        oauthGroup := router.Group("/auth/oauth")
        {
            oauthGroup.GET("/:provider", authService.OAuth.BeginAuthHandler())
            oauthGroup.GET("/:provider/callback", authService.OAuth.CompleteAuthHandler())
        }
    }

    // Protected routes
    protected := router.Group("/api/protected")
    protected.Use(authService.JWT.Middleware.MiddlewareFunc())
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
    // Implement your own SessionService
    sessionService := &MySessionService{} // Your implementation

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

        // Session service (you must provide this)
        SessionService: sessionService,

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
        // Login endpoint - creates session and sets SID cookie
        bffGroup.POST("/login", func(c *gin.Context) {
            var loginReq struct {
                Email    string `json:"email"`
                Password string `json:"password"`
            }

            if err := c.ShouldBindJSON(&loginReq); err != nil {
                c.JSON(400, gin.H{"error": "Invalid request"})
                return
            }

            // Your authentication logic here
            user, err := authenticateUser(loginReq.Email, loginReq.Password)
            if err != nil {
                c.JSON(401, gin.H{"error": "Authentication failed"})
                return
            }

            // Create session
            sid, err := sessionService.CreateSession(user, time.Hour*24*30)
            if err != nil {
                c.JSON(500, gin.H{"error": "Failed to create session"})
                return
            }

            // IMPORTANT: Manually set the SID cookie
            auth.SetSIDCookie(c, sid, auth.CookieConfig{
                Name:     "sid",
                Path:     "/",
                MaxAge:   86400 * 30,
                HttpOnly: true,
                Secure:   true,
            })

            c.JSON(200, gin.H{"message": "Login successful"})
        })

        // Session exchange for JWT (for microservice calls)
        bffGroup.POST("/exchange", func(c *gin.Context) {
            sid := auth.GetSIDCookie(c, "sid")
            if sid == "" {
                c.JSON(401, gin.H{"error": "No session"})
                return
            }

            jwt, err := bffService.BFF.Exchange.ExchangeSessionForJWT(sid)
            if err != nil {
                c.JSON(401, gin.H{"error": "Session exchange failed"})
                return
            }

            c.JSON(200, gin.H{"token": jwt})
        })

        // Session validation
        bffGroup.GET("/validate", bffService.BFF.Middleware.RequireSession(), func(c *gin.Context) {
            user, _ := c.Get("user")
            c.JSON(200, gin.H{"user": user})
        })
    }

    // OAuth endpoints (if configured)
    if bffService.OAuth != nil {
        oauthGroup := router.Group("/auth/oauth")
        {
            oauthGroup.GET("/:provider", bffService.OAuth.BeginAuthHandler())
            oauthGroup.GET("/:provider/callback", bffService.OAuth.CompleteAuthHandler())
            // Note: OAuth callbacks return user data but don't set SID cookies
            // You'll need to create a session and set the cookie in your success handler
        }
    }

    // Protected routes using BFF middleware
    protected := router.Group("/api/protected")
    protected.Use(bffService.BFF.Middleware.RequireSession())
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
- **Manual cookie management** - You must set SID cookies after creating sessions

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

**Token Lookup Priority**: Header → Query Parameter → Cookie

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

    // Session service (you must provide this)
    SessionService SessionService

    // User callbacks
    FindUserByEmail FindUserByEmailFunc
    FindUserByID    FindUserByIDFunc

    // OAuth configuration (optional)
    OAuth *OAuthConfig
}
```

### SessionService Interface (Required for BFF)

```go
type SessionService interface {
    CreateSession(user UserInfo, expiry time.Duration) (string, error)
    GetSession(sid string) (UserInfo, error)
    DeleteSession(sid string) error
    ValidateSession(sid string) (UserInfo, error)
}
```

**Important**: After creating a session with `CreateSession()`, you must manually set the SID cookie using `auth.SetSIDCookie()`. The kit does not automatically set cookies - this gives you full control over cookie configuration and timing.

### UserInfo Struct

```go
type UserInfo struct {
    ID           uint   `json:"id"`
    Email        string `json:"email"`
    Role         string `json:"role"`
    PasswordHash string `json:"-"`
}
```

## Utility Functions

```go
import "github.com/ExpanseVR/gin-auth-kit/utils"

// Password utilities
hashedPassword, err := utils.HashPassword("password123", 12)
err := utils.VerifyPassword(hashedPassword, "password123")

// Session ID generation
sid, err := utils.GenerateSecureSID()
// Returns: "sid_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"

// Cookie utilities
// After creating a session, you must manually set the SID cookie:
sid, err := sessionService.CreateSession(user, time.Hour*24*30)
if err == nil {
    auth.SetSIDCookie(c, sid, auth.CookieConfig{
        Name: "sid",
        Path: "/",
        MaxAge: 86400,
        HttpOnly: true,
        Secure: true,
    })
}

sidValue := auth.GetSIDCookie(c, "sid")
auth.ClearSIDCookie(c, "sid")
```

## Migration from v1.0.1

See [CHANGELOG.md](CHANGELOG.md) for migration guide from interface-based to callback-based design.

## Roadmap

### ✅ Completed (v1.0.2)

- [x] OAuth 2.0 authentication (Google, GitHub, Facebook)
- [x] BFF (Backend-for-Frontend) architecture support
- [x] Session-based authentication with JWT exchange
- [x] Comprehensive configuration validation
- [x] Full test coverage for all authentication methods
- [x] Secure cookie management utilities
- [x] Interface-driven SessionService design

### 🔄 In Progress

- [ ] Route integration helpers
- [ ] Advanced error handling integration
- [ ] Configuration examples and templates
- [ ] Code organization refactoring (domain-based file structure)

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
