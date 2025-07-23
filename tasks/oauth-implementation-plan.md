# OAuth Implementation Plan for Gin Auth Kit

## Overview

Adding OAuth authentication support to the existing gin-auth-kit package using Goth v2 for provider management.

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
}
```

## Interface Definition

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

## User Configuration Example

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

## Implementation Tasks

### Phase 1: Core Infrastructure

- [ ] Add new dependencies to go.mod
- [ ] Create oauth.go file for OAuth-specific code
- [ ] Define OAuthProvider and OAuthConfig structures
- [ ] Create OAuthService interface
- [ ] Update AuthOptions to include OAuth configuration

### Phase 2: Service Implementation

- [ ] Implement OAuthService interface
- [ ] Create provider registration logic
- [ ] Implement BeginAuthHandler for OAuth initiation
- [ ] Implement CompleteAuthHandler for OAuth callback
- [ ] Create user mapping function from Goth user to UserInfo

### Phase 3: Integration

- [ ] Integrate OAuth with existing auth flow
- [ ] Update main auth initialization to handle OAuth config
- [ ] Add session management for OAuth state
- [ ] Create helper functions for common OAuth operations

### Phase 4: Testing & Documentation

- [ ] Add unit tests for OAuth functionality
- [ ] Create integration tests with mock OAuth providers
- [ ] Update README with OAuth usage examples
- [ ] Add OAuth configuration documentation

## File Structure Changes

```
gin-auth-kit/
├── auth.go (updated to include OAuth)
├── interfaces.go (updated with OAuth interfaces)
├── oauth.go (new file for OAuth implementation)
├── jwt.go (existing)
├── jwt_callbacks.go (existing)
├── utils/
│   ├── http.go (existing)
│   └── password.go (existing)
└── tasks/
    └── oauth-implementation-plan.md (this file)
```

## Key Considerations

1. **Session Management**: Need to handle OAuth state securely
2. **Error Handling**: Proper error handling for OAuth failures
3. **User Mapping**: Consistent user information across JWT and OAuth flows
4. **Security**: Secure storage of client secrets and session data
5. **Flexibility**: Support for multiple OAuth providers
6. **Backward Compatibility**: Ensure existing JWT functionality remains intact

## Next Steps

1. Start with Phase 1: Core Infrastructure
2. Add dependencies and create basic structures
3. Implement the OAuthService interface
4. Test with a single provider (Google recommended for testing)
5. Expand to support additional providers as needed
