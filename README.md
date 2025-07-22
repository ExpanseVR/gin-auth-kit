# gin-auth-kit

Complete JWT and OAuth authentication toolkit for Gin web framework with clean, interface-based design.

[![Go Reference](https://pkg.go.dev/badge/github.com/ExpanseVR/gin-auth-kit.svg)](https://pkg.go.dev/github.com/ExpanseVR/gin-auth-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Features

- **JWT Authentication** - Complete JWT token management with both cookie and header support for web and API clients
- **Interface-Based Design** - Clean abstractions for User, UserRepository, and Logger
- **Session Management** - Built-in session store for OAuth flows and stateful auth
- **Password Security** - bcrypt password hashing utilities with configurable cost
- **HTTP Utilities** - SameSite cookie parsing and web security helpers
- **Configurable Options** - Flexible AuthOptions for JWT settings and security config
- **Middleware Ready** - Gin-compatible middleware for protected routes
- **Database Agnostic** - Works with any database through UserRepository interface
- **Logger Agnostic** - Works with any logging library through Logger interface
- **Production Ready** - Proper error handling, security defaults, Docker support

## Installation

```bash
go get github.com/ExpanseVR/gin-auth-kit
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

// Implement the auth.User interface
func (u *User) GetID() uint           { return u.ID }
func (u *User) GetEmail() string      { return u.Email }
func (u *User) GetRole() string       { return u.Role }
func (u *User) GetPasswordHash() string { return u.PasswordHash }
```

### 2. Create Repository Adapter

```go
type UserRepository struct {
    db *gorm.DB
}

func (r *UserRepository) FindByEmail(email string) (auth.User, error) {
    var user User
    err := r.db.Where("email = ?", email).First(&user).Error
    if err != nil {
        return nil, err
    }
    return &user, nil
}

func (r *UserRepository) FindByID(id uint) (auth.User, error) {
    var user User
    err := r.db.Where("id = ?", id).First(&user).Error
    if err != nil {
        return nil, err
    }
    return &user, nil
}
```

### 3. Setup Authentication Service

```go
import "github.com/ExpanseVR/gin-auth-kit"

func main() {
    // Configure authentication options
    opts := &auth.AuthOptions{
        JWTSecret:         "your-jwt-secret",
        JWTRealm:         "your-app",
        TokenExpireTime:  time.Hour,
        RefreshExpireTime: 7 * 24 * time.Hour,
        IdentityKey:      "user_id",
        SessionSecret:    "your-session-secret",
        SessionMaxAge:    86400,
        BcryptCost:       12,
    }

    // Create adapters
    userRepo := &UserRepository{db: db}
    logger := &LoggerAdapter{logger: log.Logger}

    // Initialize auth service
    authService, err := auth.NewAuthService(opts, userRepo, logger)
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    router := gin.Default()

    // Auth routes
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

### 4. Logger Adapter Example

```go
type LoggerAdapter struct {
    logger *zerolog.Logger
}

func (l *LoggerAdapter) Error() auth.LogEvent {
    return &LogEventAdapter{event: l.logger.Error()}
}

func (l *LoggerAdapter) Warn() auth.LogEvent {
    return &LogEventAdapter{event: l.logger.Warn()}
}

func (l *LoggerAdapter) Debug() auth.LogEvent {
    return &LogEventAdapter{event: l.logger.Debug()}
}

type LogEventAdapter struct {
    event *zerolog.Event
}

func (e *LogEventAdapter) Err(err error) auth.LogEvent {
    return &LogEventAdapter{event: e.event.Err(err)}
}

func (e *LogEventAdapter) Msg(msg string) {
    e.event.Msg(msg)
}

func (e *LogEventAdapter) Str(key, val string) auth.LogEvent {
    return &LogEventAdapter{event: e.event.Str(key, val)}
}

func (e *LogEventAdapter) Uint(key string, val uint) auth.LogEvent {
    return &LogEventAdapter{event: e.event.Uint(key, val)}
}
```

# Token Handling

gin-auth-kit supports **multiple token delivery methods** for maximum flexibility:

### **Cookie-Based (Recommended for Web Apps)**

- **Automatic:** Tokens stored in secure, HTTP-only cookies
- **CSRF Protection:** Built-in SameSite cookie settings
- **Frontend:** No token management required
- **Use Case:** Traditional web applications, server-side rendered apps

```javascript
// Frontend - No token management needed!
fetch("/api/protected/profile", {
  method: "GET",
  credentials: "include", // Include cookies automatically
});
```

### **Header-Based (API/SPA)**

- **Manual:** Frontend manages token storage and headers
- **Flexible:** Works with SPAs, mobile apps, API clients
- **CORS-friendly:** Standard Authorization header
- **Use Case:** Single-page applications, mobile apps, API integrations

```javascript
// Frontend - Manual token management
const token = localStorage.getItem("jwt_token");
fetch("/api/protected/profile", {
  headers: {
    Authorization: `Bearer ${token}`,
  },
});
```

### **Hybrid Mode (Default)**

gin-auth-kit automatically supports **both approaches simultaneously**:

- Checks `Authorization` header first
- Falls back to `jwt` cookie if no header
- Also supports query parameter `?token=...` for special cases

**Token Lookup Order:**

1. `Authorization: Bearer <token>` header
2. `jwt` cookie
3. `?token=<token>` query parameter

## Configuration

### AuthOptions

```go
type AuthOptions struct {
    // JWT Configuration
    JWTSecret           string
    JWTRealm           string
    TokenExpireTime    time.Duration
    RefreshExpireTime  time.Duration
    IdentityKey        string

    // Session Configuration
    SessionSecret string
    SessionMaxAge int
    SessionDomain string
    SessionSecure bool
    SessionSameSite string

    // Security Settings
    BcryptCost int
}
```

## Testing

The package includes test utilities for password hashing:

```go
import "github.com/ExpanseVR/gin-auth-kit/utils"

// Hash a password
hashedPassword, err := utils.HashPassword("password123", 12)

// Verify a password
err := utils.VerifyPassword(hashedPassword, "password123")
```

## Roadmap

- [ ] OAuth 2.0 providers (Google, Facebook, Apple)
- [ ] Role-Based Access Control (RBAC)
- [ ] API Key authentication
- [ ] Rate limiting middleware
- [ ] Account lockout protection
- [ ] Password reset flows
- [ ] Multi-factor authentication (MFA)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on top of [gin-jwt](https://github.com/appleboy/gin-jwt) middleware
- Inspired by clean architecture principles
- Designed for production use in modern Go applications
