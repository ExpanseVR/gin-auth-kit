# gin-auth-kit

Complete authentication toolkit for Gin web framework with JWT, OAuth, and BFF (Backend-for-Frontend) support. Clean, callback-based design with production-ready features.

[![Go Reference](https://pkg.go.dev/badge/github.com/ExpanseVR/gin-auth-kit.svg)](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Which Authentication Method Should I Choose?](#-which-authentication-method-should-i-choose)
- [Common Configuration](#common-configuration)
- [Quick Start](#quick-start)
- [Examples](#examples)
- [Helper Functions](#helper-functions)
- [Advanced Configuration](#advanced-configuration)
- [Production Deployment](#production-deployment)
- [Authentication Methods](#authentication-methods)
- [Token Handling](#token-handling)
- [Configuration](#configuration)
- [Migration from v1.0.1](#migration-from-v1001)
- [Roadmap](#roadmap)
- [Architecture Patterns](#architecture-patterns)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

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

## 🤔 Which Authentication Method Should I Choose?

| Method    | Best For                       | Security Level | Setup Complexity | Token Storage |
| --------- | ------------------------------ | -------------- | ---------------- | ------------- |
| **JWT**   | APIs, Mobile Apps, SPAs        | Good           | Low              | Client-side   |
| **OAuth** | Social login, Third-party auth | Good           | Medium           | Client-side   |
| **BFF**   | Web apps, Microservices        | Highest        | High             | Server-side   |

**Choose JWT** if you're building an API or mobile app where clients can securely store tokens.

**Choose OAuth** if you need social login (Google, GitHub, etc.) or third-party authentication.

**Choose BFF** if you're building a web application with microservices and want maximum security (tokens never reach the browser).

## Common Configuration

### Basic Setup

```go
opts := &auth.AuthOptions{
    JWTSecret: "your-secret-key",
    JWTRealm:  "my-app",
    FindUserByEmail: findUserByEmail,
    FindUserByID:    findUserByID,
}
```

### Required Callbacks

```go
func findUserByEmail(email string) (auth.UserInfo, error) {
    // Your database lookup logic
    return auth.UserInfo{ID: 1, Email: email, Role: "user"}, nil
}

func findUserByID(id uint) (auth.UserInfo, error) {
    // Your database lookup logic
    return auth.UserInfo{ID: id, Email: "user@example.com"}, nil
}
```

**Note**: These callbacks are required for all authentication methods. See [Configuration](#configuration) section for complete `AuthOptions` and `BFFAuthOptions` documentation.

## Quick Start

Choose your authentication method and get running in under 5 minutes:

## 🚀 Quick Start: JWT Authentication

Perfect for APIs and single-page applications.

```go
package main

import (
    "errors"
    "log"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

// User callback functions (see [Common Configuration](#common-configuration))

func main() {
    // Use common configuration (see above)
    opts := &auth.AuthOptions{
        JWTSecret:       "your-secret-key-change-in-production",
        JWTRealm:        "my-app",
        FindUserByEmail: findUserByEmail, // See [Common Configuration](#common-configuration)
        FindUserByID:    findUserByID,    // See [Common Configuration](#common-configuration)
    }

    authService, err := auth.NewAuthService(opts)
    if err != nil {
        log.Fatal("Auth setup failed:", err)
    }

    router := gin.Default()

    // Login endpoint
    router.POST("/login", authService.JWT.Middleware.LoginHandler())

    // Protected endpoint
    router.GET("/profile",
        authService.JWT.Middleware.MiddlewareFunc(),
        func(c *gin.Context) {
            // Get user ID from JWT context
            userID, exists := c.Get("user_id")
            if !exists {
                c.JSON(500, gin.H{"error": "User ID not found"})
                return
            }
            c.JSON(200, gin.H{"user_id": userID, "message": "Welcome!"})
        },
    )

    log.Println("Server running on :8080")
    log.Println("Try: curl -X POST http://localhost:8080/login -d '{\"email\":\"user@example.com\",\"password\":\"password123\"}' -H 'Content-Type: application/json'")

    router.Run(":8080")
}
```

**Test it:**

```bash
# Login to get JWT token
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Use the token (replace YOUR_TOKEN with the actual token)
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/profile
```

---

## 🔐 Quick Start: OAuth Authentication

Perfect for social login (Google, GitHub, etc.).

```go
package main

import (
    "errors"
    "log"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

func main() {
    opts := &auth.AuthOptions{
        JWTSecret: "your-secret-key",
        JWTRealm:  "my-app",

        // OAuth configuration
        OAuth: &auth.OAuthConfig{
            Providers: map[string]auth.OAuthProvider{
                "google": {
                    ClientID:     "your-google-client-id",
                    ClientSecret: "your-google-client-secret",
                    RedirectURL:  "http://localhost:8080/auth/google/callback",
                    Scopes:       []string{"email", "profile"},
                },
            },
            BaseURL:    "http://localhost:8080",
            SuccessURL: "/dashboard",
            FailureURL: "/login?error=oauth_failed",
        },

        // User callbacks (see [Common Configuration](#common-configuration))
        FindUserByEmail: findUserByEmail,
        FindUserByID:    findUserByID,
    }

    authService, err := auth.NewAuthService(opts)
    if err != nil {
        log.Fatal("Auth setup failed:", err)
    }

    router := gin.Default()

    // OAuth endpoints
    router.GET("/auth/:provider", authService.OAuth.BeginAuthHandler())
    router.GET("/auth/:provider/callback", authService.OAuth.CompleteAuthHandler())

    // Success page
    router.GET("/dashboard", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "OAuth login successful!"})
    })

    // Protected endpoint
    router.GET("/profile",
        authService.JWT.Middleware.MiddlewareFunc(),
        func(c *gin.Context) {
            // Get user ID from JWT context
            userID, exists := c.Get("user_id")
            if !exists {
                c.JSON(500, gin.H{"error": "User ID not found"})
                return
            }
            c.JSON(200, gin.H{"user_id": userID})
        },
    )

    log.Println("Server running on :8080")
    log.Println("Visit: http://localhost:8080/auth/google")

    router.Run(":8080")
}
```

**Test it:**

1. Set up Google OAuth credentials in [Google Console](https://console.developers.google.com)
2. Visit `http://localhost:8080/auth/google`
3. Complete OAuth flow
4. Access protected routes with the JWT token received

---

## 🛡️ Quick Start: BFF (Backend-for-Frontend)

Perfect for web applications with maximum security - JWT tokens never reach the browser.

```go
package main

import (
    "errors"
    "log"
    "time"
    "sync"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
    "github.com/ExpanseVR/gin-auth-kit/utils"
)

// Simple in-memory session store (use Redis/Database in production)
type SimpleSessionStore struct {
    sessions map[string]auth.UserInfo
    mutex    sync.RWMutex
}

func (s *SimpleSessionStore) CreateSession(user auth.UserInfo, expiry time.Duration) (string, error) {
    sid, err := utils.GenerateSecureSID()
    if err != nil {
        return "", err
    }

    s.mutex.Lock()
    s.sessions[sid] = user
    s.mutex.Unlock()

    return sid, nil
}

func (s *SimpleSessionStore) ValidateSession(sid string) (auth.UserInfo, error) {
    s.mutex.RLock()
    user, exists := s.sessions[sid]
    s.mutex.RUnlock()

    if !exists {
        return auth.UserInfo{}, errors.New("session not found")
    }
    return user, nil
}

func (s *SimpleSessionStore) GetSession(sid string) (auth.UserInfo, error) {
    return s.ValidateSession(sid)
}

func (s *SimpleSessionStore) DeleteSession(sid string) error {
    s.mutex.Lock()
    delete(s.sessions, sid)
    s.mutex.Unlock()
    return nil
}

func main() {
    // Simple session store
    sessionStore := &SimpleSessionStore{
        sessions: make(map[string]auth.UserInfo),
    }

    // BFF configuration
    opts := &auth.BFFAuthOptions{
        JWTSecret:     "your-jwt-secret",
        JWTExpiry:     10 * time.Minute,
        SessionSecret: "your-session-secret",
        SessionMaxAge: 86400, // 24 hours
        SIDCookieName: "sid",
        SessionService: sessionStore,

        FindUserByEmail: findUserByEmail, // See [Common Configuration](#common-configuration)
        FindUserByID:    findUserByID,    // See [Common Configuration](#common-configuration)
    }

    bffService, err := auth.NewBFFAuthService(opts)
    if err != nil {
        log.Fatal("BFF setup failed:", err)
    }

    router := gin.Default()

    // Login endpoint (creates session + sets cookie)
    router.POST("/login", func(c *gin.Context) {
        var loginReq struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }

        if err := c.ShouldBindJSON(&loginReq); err != nil {
            c.JSON(400, gin.H{"error": "Invalid request"})
            return
        }

        // Authenticate user (simplified)
        if loginReq.Email == "user@example.com" && loginReq.Password == "password123" {
            user := auth.UserInfo{ID: 1, Email: loginReq.Email, Role: "user"}

            // Create session
            sid, err := sessionStore.CreateSession(user, 24*time.Hour)
            if err != nil {
                c.JSON(500, gin.H{"error": "Session creation failed"})
                return
            }

            // Set secure cookie using Gin's built-in function
            c.SetCookie(
                "sid",           // name
                sid,             // value
                86400,           // max age (24 hours)
                "/",             // path
                "",              // domain
                false,           // secure (set true in production with HTTPS)
                true,            // httpOnly
            )

            c.JSON(200, gin.H{"message": "Login successful"})
        } else {
            c.JSON(401, gin.H{"error": "Invalid credentials"})
        }
    })

    // JWT exchange endpoint (for microservice calls)
    router.POST("/exchange",
        bffService.BFF.Middleware.RequireSession(),
        func(c *gin.Context) {
            // Get SID from cookie using Gin's built-in function
            sid, err := c.Cookie("sid")
            if err != nil || sid == "" {
                c.JSON(401, gin.H{"error": "No session"})
                return
            }

            // Exchange session for JWT
            jwt, err := bffService.BFF.Exchange.ExchangeSessionForJWT(sid)
            if err != nil {
                c.JSON(500, gin.H{"error": "Token generation failed"})
                return
            }
            c.JSON(200, gin.H{"jwt": jwt})
        },
    )

    // Protected endpoint
    router.GET("/profile",
        bffService.BFF.Middleware.RequireSession(),
        func(c *gin.Context) {
            // Get user from session context (set by middleware)
            user, exists := c.Get("user")
            if !exists {
                c.JSON(500, gin.H{"error": "User not found"})
                return
            }
            userInfo := user.(auth.UserInfo)
            c.JSON(200, gin.H{
                "user_id": userInfo.ID,
                "email":   userInfo.Email,
                "message": "Accessed via secure session!",
            })
        },
    )

    log.Println("Server running on :8080")
    log.Println("Try: curl -X POST http://localhost:8080/login -d '{\"email\":\"user@example.com\",\"password\":\"password123\"}' -H 'Content-Type: application/json' -c cookies.txt")
    log.Println("Then: curl -b cookies.txt http://localhost:8080/profile")

    router.Run(":8080")
}
```

**Test it:**

```bash
# Login and save cookies
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}' \
  -c cookies.txt

# Access protected route using session cookie
curl -b cookies.txt http://localhost:8080/profile

# Get JWT token for microservice calls
curl -X POST http://localhost:8080/exchange -b cookies.txt
```

> ⚠️ **Security Note**: Set `Secure: true` for `c.SetCookie` in production and use HTTPS to prevent token leakage.

## Next Steps

- **Complete Examples**: See [Examples](#examples)
- **Helper Functions**: See [Helper Functions](#helper-functions)
- **Production Setup**: See [Advanced Configuration](#advanced-configuration)

## Examples

### BFF Authentication Example

**Location**: `examples/bff_example/`

Complete BFF authentication with session-based security and JWT exchange.

**Quick Test**:

```bash
cd examples/bff_example
go run main.go                    # Start server
./test.sh                         # Run automated tests
rm -f cookies.txt                 # Clean up test cookies
```

> **Note**: For production, use environment variables and proper session storage (Redis/Database).

## Helper Functions

gin-auth-kit provides convenient helper functions for common operations:

### Context Helpers

```go
import "github.com/ExpanseVR/gin-auth-kit"

// Extract user ID from JWT context (after JWT middleware)
userID, exists := c.Get("user_id")
if exists {
    id := userID.(uint)
}

// Extract full user info from session context (after BFF middleware)
user, exists := c.Get("user")
if exists {
    userInfo := user.(auth.UserInfo)
}
```

### Cookie Management

```go
// Set secure SID cookie using Gin's built-in function
c.SetCookie(
    "sid",           // name
    sid,             // value
    86400,           // max age (24 hours)
    "/",             // path
    "",              // domain
    true,            // secure (HTTPS only)
    true,            // httpOnly
)

// Get SID from cookie using Gin's built-in function
sid, err := c.Cookie("sid")

// Clear SID cookie (logout) using Gin's built-in function
c.SetCookie(
    "sid",    // name
    "",       // value (empty to clear)
    -1,       // max age (negative to delete)
    "/",      // path
    "",       // domain
    false,    // secure
    true,     // httpOnly
)
```

### Password Utilities

```go
import "golang.org/x/crypto/bcrypt"

// Hash password with bcrypt
hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), 12)

// Verify password
err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte("password123"))

// Generate secure session ID (example)
sid := "sid_" + time.Now().Format("20060102150405") + "_" + userEmail
// In production, use crypto/rand for secure session IDs
```

**Note**: Context helpers work after the respective middleware has processed the request. Cookie management functions are available for manual cookie handling in BFF scenarios.

## Advanced Configuration

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

See the **BFF Implementation Steps** section below for detailed setup instructions. Here's a complete working example:

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/ExpanseVR/gin-auth-kit"
)

func main() {
    // Your SessionService implementation (see Step 1 below)
    sessionService := &MySessionService{db: myDB}

    // BFF configuration (see Step 2 below)
    opts := &auth.BFFAuthOptions{
        SessionSecret: "your-session-secret",
        SessionMaxAge: 86400 * 30,
        SessionDomain: ".yourapp.com",
        SessionSecure: true,
        JWTSecret: "your-jwt-secret",
        JWTExpiry: 10 * time.Minute,
        SIDCookieName: "sid",
        SIDCookiePath: "/",
        SessionService: sessionService,
        FindUserByEmail: findUserByEmail,
        FindUserByID:    findUserByID,
    }

    // Initialize BFF service (see Step 3 below)
    bffService, err := auth.NewBFFAuthService(opts)
    if err != nil {
        log.Fatal("Failed to create BFF auth service:", err)
    }

    router := gin.Default()

    // Set up routes and cookie management (see Step 4 below)
    bffGroup := router.Group("/api/bff")
    {
        bffGroup.POST("/login", loginHandler(bffService))
        bffGroup.POST("/exchange", exchangeHandler(bffService))
        bffGroup.GET("/validate", bffService.BFF.Middleware.RequireSession(), validateHandler)
    }

    protected := router.Group("/api/protected")
    protected.Use(bffService.BFF.Middleware.RequireSession())
    {
        protected.GET("/profile", getProfile)
    }

    router.Run(":8080")
}
```

## Production Deployment

### Security Checklist

**🔒 Secrets Management**

```go
// ❌ Never hardcode secrets
JWTSecret: "your-secret-key"

// ✅ Use environment variables
JWTSecret: os.Getenv("JWT_SECRET")
SessionSecret: os.Getenv("SESSION_SECRET")

```

### Environment Configuration

**.env file:**

```bash
# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-min-32-chars
JWT_REALM=your-app-name

# Session Configuration
SESSION_SECRET=your-super-secure-session-secret-min-32-chars

# OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Database
DATABASE_URL=postgres://user:pass@localhost/dbname?sslmode=require

# Security
COOKIE_DOMAIN=.yourdomain.com
COOKIE_SECURE=true
```

**Production Code:**

```go
import (
    "os"
    "log"
    "github.com/joho/godotenv"
)

func main() {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, using system environment")
    }

    opts := &auth.AuthOptions{
        JWTSecret:     getEnvOrPanic("JWT_SECRET"),
        SessionSecret: getEnvOrPanic("SESSION_SECRET"),
        SessionSecure: getEnvBool("COOKIE_SECURE", true),
        SessionDomain: os.Getenv("COOKIE_DOMAIN"),

        OAuth: &auth.OAuthConfig{
            Providers: map[string]auth.OAuthProvider{
                "google": {
                    ClientID:     getEnvOrPanic("GOOGLE_CLIENT_ID"),
                    ClientSecret: getEnvOrPanic("GOOGLE_CLIENT_SECRET"),
                    RedirectURL:  os.Getenv("BASE_URL") + "/auth/google/callback",
                    Scopes:       []string{"email", "profile"},
                },
            },
        },

        FindUserByEmail: findUserByEmail, // Your database lookup
        FindUserByID:    findUserByID,    // Your database lookup
    }

    // ... rest of setup
}

func getEnvOrPanic(key string) string {
    value := os.Getenv(key)
    if value == "" {
        log.Fatalf("Environment variable %s is required", key)
    }
    return value
}

func getEnvBool(key string, defaultValue bool) bool {
    value := os.Getenv(key)
    if value == "" {
        return defaultValue
    }
    return value == "true"
}
```

### Session Storage Options

**Redis (Recommended for Production)**

```go
import (
    "context"
    "encoding/json"
    "time"
    "github.com/go-redis/redis/v8"
)

type RedisSessionService struct {
    client *redis.Client
}

func (r *RedisSessionService) CreateSession(user auth.UserInfo, expiry time.Duration) (string, error) {
    sid, err := utils.GenerateSecureSID()
    if err != nil {
        return "", err
    }

    userData, _ := json.Marshal(user)
    err = r.client.Set(context.Background(), sid, userData, expiry).Err()
    return sid, err
}

func (r *RedisSessionService) ValidateSession(sid string) (auth.UserInfo, error) {
    data, err := r.client.Get(context.Background(), sid).Result()
    if err != nil {
        return auth.UserInfo{}, err
    }

    var user auth.UserInfo
    err = json.Unmarshal([]byte(data), &user)
    return user, err
}

func (r *RedisSessionService) GetSession(sid string) (auth.UserInfo, error) {
    return r.ValidateSession(sid)
}

func (r *RedisSessionService) DeleteSession(sid string) error {
    return r.client.Del(context.Background(), sid).Err()
}
```

**Database Sessions**

```go
import (
    "database/sql"
    "time"
)

type DBSessionService struct {
    db *sql.DB
}

func (d *DBSessionService) CreateSession(user auth.UserInfo, expiry time.Duration) (string, error) {
    sid, err := utils.GenerateSecureSID()
    if err != nil {
        return "", err
    }

    expiresAt := time.Now().Add(expiry)
    _, err = d.db.Exec(`
        INSERT INTO sessions (sid, user_id, expires_at)
        VALUES ($1, $2, $3)
    `, sid, user.ID, expiresAt)

    return sid, err
}

func (d *DBSessionService) ValidateSession(sid string) (auth.UserInfo, error) {
    var userID uint
    var expiresAt time.Time

    err := d.db.QueryRow(`
        SELECT user_id, expires_at FROM sessions
        WHERE sid = $1 AND expires_at > NOW()
    `, sid).Scan(&userID, &expiresAt)

    if err != nil {
        return auth.UserInfo{}, err
    }

    // Fetch user details
    return d.FindUserByID(userID)
}

func (d *DBSessionService) GetSession(sid string) (auth.UserInfo, error) {
    return d.ValidateSession(sid)
}

func (d *DBSessionService) DeleteSession(sid string) error {
    _, err := d.db.Exec("DELETE FROM sessions WHERE sid = $1", sid)
    return err
}
```

### Monitoring & Logging

**Add request logging:**

```go
import (
    "fmt"
    "time"
    "github.com/gin-gonic/gin"
)

// Log authentication events
router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
    return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
        param.ClientIP,
        param.TimeStamp.Format(time.RFC1123),
        param.Method,
        param.Path,
        param.Request.Proto,
        param.StatusCode,
        param.Latency,
        param.Request.UserAgent(),
        param.ErrorMessage,
    )
}))
```

**Monitor failed login attempts:**

```go
// Track failed attempts in your FindUserByEmail callback
func findUserByEmail(email string) (auth.UserInfo, error) {
    user, err := db.GetUserByEmail(email)
    if err != nil {
        // Log failed attempt
        log.Printf("Failed login attempt for email: %s", email)
        return auth.UserInfo{}, err
    }
    return user, nil
}
```

### Performance Optimization

**Connection Pooling:**

```go
// Configure database connection pool
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(25)
db.SetConnMaxLifetime(5 * time.Minute)
```

**Session Cleanup:**

```go
// Regular cleanup of expired sessions
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        sessionService.CleanupExpiredSessions()
    }
}()
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

#### BFF Implementation Steps

**Step 1: Implement SessionService Interface**

```go
type MySessionService struct {
    db *sql.DB  // Your database connection
}

func (m *MySessionService) CreateSession(user UserInfo, expiry time.Duration) (string, error) {
    // Your session creation logic - store in database/Redis/etc.
    sid := utils.GenerateSecureSID()
    // Store sid -> user mapping in your database
    return sid, nil
}

func (m *MySessionService) ValidateSession(sid string) (UserInfo, error) {
    // Your session validation logic - lookup from database/Redis/etc.
    // Return user info if session is valid
    return userInfo, nil
}

func (m *MySessionService) GetSession(sid string) (UserInfo, error) {
    // Your session retrieval logic
    return userInfo, nil
}

func (m *MySessionService) DeleteSession(sid string) error {
    // Your session deletion logic
    return nil
}
```

**Step 2: Create BFFAuthOptions Configuration**

```go
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

    // Your SessionService implementation
    SessionService: &MySessionService{db: myDB},

    // User callbacks
    FindUserByEmail: findUserByEmail,
    FindUserByID:    findUserByID,
}
```

**Step 3: Initialize BFF Service**

```go
bffService, err := auth.NewBFFAuthService(opts)
if err != nil {
    log.Fatal("Failed to create BFF auth service:", err)
}
```

**Step 4: Set Up Routes and Manual Cookie Management**

```go
// Login endpoint - you create session and set cookie
bffGroup.POST("/login", func(c *gin.Context) {
    // Your authentication logic
    user, err := authenticateUser(email, password)
    if err != nil {
        c.JSON(401, gin.H{"error": "Authentication failed"})
        return
    }

    // Create session using your SessionService
    sid, err := bffService.BFF.Sessions.CreateSession(user, time.Hour*24*30)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create session"})
        return
    }

    // IMPORTANT: Manually set the SID cookie using Gin's built-in function
    c.SetCookie(
        "sid",           // name
        sid,             // value
        86400 * 30,      // max age (30 days)
        "/",             // path
        "",              // domain
        true,            // secure (HTTPS only)
        true,            // httpOnly
    )

    c.JSON(200, gin.H{"message": "Login successful"})
})

// Protected routes using BFF middleware
protected := router.Group("/api/protected")
protected.Use(bffService.BFF.Middleware.RequireSession())
{
    protected.GET("/profile", getProfile)
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

**Token Lookup Priority**: Header → Query Parameter → Cookie

## Configuration

### AuthOptions (Traditional + OAuth)

See [Go Reference](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit#AuthOptions) for complete configuration options.

### UserInfo Struct

```go
type UserInfo struct {
    ID           uint           `json:"id"`
    Email        string         `json:"email"`
    Role         string         `json:"role"`
    FirstName    string         `json:"first_name,omitempty"`
    LastName     string         `json:"last_name,omitempty"`
    PasswordHash string         `json:"-"`
    CustomFields map[string]any `json:"custom_fields,omitempty"`
}
```

The `UserInfo` struct is designed to be extensible. You can:

1. **Use built-in fields** - `FirstName`, `LastName` for basic user information
2. **Use CustomFields** - Store additional data using `SetCustomField()` and `GetCustomField()`
3. **Embed in custom structs** - Create your own user struct that embeds `UserInfo`

See [Extensible User Example](examples/extensible_user_example/) for detailed patterns and usage examples.

## Migration from v1.0.1

See [CHANGELOG.md](CHANGELOG.md) for migration guide from interface-based to callback-based design.

## Roadmap

### ✅ Completed (v1.0.3)

- [x] Extensible UserInfo struct with FirstName, LastName, and CustomFields
- [x] Four extensibility patterns (embedding, custom fields, custom methods, factory)
- [x] Enhanced OAuth integration with automatic field mapping
- [x] JWT token support for custom fields

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
