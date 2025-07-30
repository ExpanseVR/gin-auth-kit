# OAuth Implementation Plan for Gin Auth Kit

## Overview

Adding OAuth authentication support to the existing gin-auth-kit package using Goth v2 for provider management, with a focus on supporting Backend-for-Frontend (BFF) architecture patterns.

## Architecture Pattern

### BFF Authentication Flow

- **Browser**: Stores only secure, httpOnly SID (Session ID) cookie
- **Next.js BFF**: Manages JWT exchange and caching, acts as authentication proxy
- **Go Server**: Handles session storage, JWT generation, and API processing

### Phase Distinction

- **Phase 1**: Database-Driven (Current Priority)
  - Session lookup via database on every request
  - Fresh JWT generation per request
  - Simple, reliable foundation
- **Phase 2**: Redis-Optimized (Future)
  - JWT caching in Redis with TTL matching JWT expiry
  - Eliminates database lookups for cached JWTs
  - Fallback to database when cache misses

## Dependencies to Add

```go
github.com/markbates/goth/v2 v2.x.x
github.com/markbates/goth/v2/gothic v2.x.x
github.com/gorilla/sessions v1.x.x
```

## Core Structures

### OAuthProvider

```go
type OAuthProvider struct {
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string
}
```

### OAuthConfig

```go
type OAuthConfig struct {
    Providers    map[string]OAuthProvider
    SessionStore sessions.Store
    BaseURL      string
    SuccessURL   string
    FailureURL   string

    // User management callbacks
    FindUserByEmail FindUserByEmailFunc
    FindUserByID    FindUserByIDFunc
}
```

### BFFAuthOptions (New)

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

## Interface Definitions

### OAuthService Interface

```go
type OAuthService interface {
    // Provider management
    RegisterProvider(name string, provider goth.Provider)
    GetProvider(name string) (goth.Provider, error)

    // OAuth flow handlers
    BeginAuthHandler() gin.HandlerFunc
    CompleteAuthHandler() gin.HandlerFunc

    // User mapping
    MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error)
}
```

### SessionService Interface (New)

```go
type SessionService interface {
    CreateSession(user UserInfo, expiry time.Duration) (string, error)
    GetSession(sid string) (UserInfo, error)
    DeleteSession(sid string) error
    ValidateSession(sid string) (UserInfo, error)
}
```

### SessionExchangeService Interface (New)

```go
type SessionExchangeService interface {
    ExchangeSessionForJWT(sid string) (string, error)
    RefreshSessionJWT(sid string) (string, error)
}
```

### BFFAuthMiddleware Interface (New)

```go
type BFFAuthMiddleware interface {
    RequireSession() gin.HandlerFunc
    RequireValidSession() gin.HandlerFunc
    OptionalSession() gin.HandlerFunc
}
```

## Package vs Project Responsibilities

### Gin-Auth-Kit Package Responsibilities

- ✅ Session Service - Core SID management
- ✅ JWT Exchange Service - Session-to-JWT conversion
- ✅ BFF Auth Middleware - Session-based protection
- ✅ Cookie management utilities
- ✅ Configuration options and validation
- ✅ OAuth provider management and flow handlers

### Implementing Project Responsibilities

- 🔧 Database integration (SessionStore, UserStore interfaces)
- 🔧 Route setup and configuration
- 🔧 Business logic integration (user roles, permissions)
- 🔧 Application-specific authentication flows

## User Configuration Example

### Traditional OAuth Setup

```go
opts := &auth.AuthOptions{
    // ... existing JWT config
    OAuth: &auth.OAuthConfig{
        Providers: map[string]auth.OAuthProvider{
            "google": {
                ClientID:     "your-google-client-id",
                ClientSecret: "your-google-client-secret",
                RedirectURL:  "https://yourapp.com/auth/oauth/google/callback",
                Scopes:       []string{"email", "profile"},
            },
        },
        SessionStore: createSessionStore("your-session-secret"),
        BaseURL:      "https://yourapp.com",
        SuccessURL:   "/dashboard",
        FailureURL:   "/login?error=oauth_failed",
    },
}
```

### BFF Setup (New)

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

    // User callbacks
    FindUserByEmail: findUserByEmail,
    FindUserByID:    findUserByID,

    // Optional OAuth configuration
    OAuth: &auth.OAuthConfig{
        // ... OAuth config
    },
}
```

## Implementation Tasks

### Phase 1: Core Infrastructure

- [ ] Add new dependencies to go.mod
- [ ] Create oauth.go file for OAuth-specific code
- [ ] Create session.go file for session management
- [ ] Create jwt_exchange.go file for BFF JWT exchange
- [ ] Create bff_middleware.go file for BFF auth middleware
- [ ] Define OAuthProvider and OAuthConfig structures
- [ ] Define BFFAuthOptions structure
- [ ] Create OAuthService, SessionService, SessionExchangeService interfaces
- [ ] Create BFFAuthMiddleware interface
- [ ] Update AuthOptions to include OAuth configuration

### Phase 2: Service Implementation

- [ ] Implement OAuthService interface
- [ ] Implement SessionService interface
- [ ] Implement SessionExchangeService interface
- [ ] Implement BFFAuthMiddleware interface
- [ ] Create provider registration logic
- [ ] Implement BeginAuthHandler for OAuth initiation
- [ ] Implement CompleteAuthHandler for OAuth callback
- [ ] Create user mapping function from Goth user to UserInfo
- [ ] Implement session-to-JWT exchange logic
- [ ] Create cookie management utilities

### Phase 3: Integration

- [ ] Integrate OAuth with existing auth flow
- [ ] Integrate BFF services with existing auth flow
- [ ] Update main auth initialization to handle OAuth and BFF config
- [ ] Add session management for OAuth state
- [ ] Create helper functions for common OAuth operations
- [ ] Create helper functions for BFF operations
- [ ] Ensure backward compatibility with existing JWT-only configurations

### Phase 4: Testing & Documentation

- [ ] Add unit tests for OAuth functionality
- [ ] Add unit tests for BFF functionality
- [ ] Create integration tests with mock OAuth providers
- [ ] Create integration tests for BFF flow
- [ ] Update README with OAuth and BFF usage examples
- [ ] Add OAuth and BFF configuration documentation
- [ ] Create setup guides for common providers and BFF patterns

## File Structure Changes

```
gin-auth-kit/
├── auth.go (updated to include OAuth and BFF)
├── interfaces.go (updated with OAuth and BFF interfaces)
├── oauth.go (OAuth implementation)
├── session.go (new - session management)
├── jwt_exchange.go (new - BFF JWT exchange)
├── bff_middleware.go (new - BFF auth middleware)
├── cookie_utils.go (new - cookie management)
├── jwt.go (existing)
├── jwt_callbacks.go (existing)
├── utils/
│   ├── http.go (existing)
│   └── password.go (existing)
└── tasks/
    └── oauth-implementation-plan.md (this file)
```

## Key Considerations

1. **Session Management**: Need to handle OAuth state and BFF sessions securely
2. **Error Handling**: Proper error handling for OAuth and BFF failures
3. **User Mapping**: Consistent user information across JWT, OAuth, and BFF flows
4. **Security**: Secure storage of client secrets, session data, and JWT tokens
5. **Flexibility**: Support for multiple OAuth providers and BFF patterns
6. **Backward Compatibility**: Ensure existing JWT functionality remains intact
7. **Performance**: Optimize for database-driven (Phase 1) and Redis-optimized (Phase 2) patterns
8. **Separation of Concerns**: Clear distinction between package responsibilities and project responsibilities

## Next Steps

1. Start with Phase 1: Core Infrastructure
2. Add dependencies and create basic structures
3. Implement the OAuthService, SessionService, and SessionExchangeService interfaces
4. Test with a single provider (Google recommended for testing)
5. Implement BFF middleware and cookie utilities
6. Expand to support additional providers and BFF patterns as needed
