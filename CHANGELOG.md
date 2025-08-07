# CHANGELOG

## [1.0.3] – 2025‑08‑07

### Added

#### Extensible UserInfo Struct

- **FirstName and LastName fields** - Added `FirstName` and `LastName` fields to `UserInfo` struct for basic user information
- **CustomFields support** - Added `CustomFields map[string]any` for extensible user data storage
- **Helper methods** - Added `GetFullName()`, `SetCustomField()`, and `GetCustomField()` methods
- **Extensible patterns** - Support for embedding `UserInfo` in custom structs and using `CustomFields` directly
- **Extensible User Example** - Comprehensive example showing four different patterns for extending `UserInfo`

#### Enhanced OAuth Integration

- **Improved User Mapping** - Enhanced `MapGothUserToUserInfo` to handle UserID conversion and extract first/last names
- **Custom Field Mapping** - Automatic mapping of OAuth provider data to `CustomFields`
- **Better JWT Integration** - Custom fields from OAuth providers are included in JWT tokens

### Changed

#### JWT Token Structure

- **Extended Claims** - JWT tokens now include `first_name`, `last_name`, and custom fields (prefixed with `custom_`)
- **Backward Compatibility** - Existing tokens continue to work, new fields are optional

## [1.0.2] – 2025‑08‑04

### Added

#### OAuth 2.0 Authentication

- **OAuth Provider Support** - Google, GitHub, Facebook, and custom providers via Goth library
- **OAuthService** - Provider registration, OAuth flow handlers (`BeginAuthHandler`, `CompleteAuthHandler`)
- **User Mapping** - Automatic conversion from OAuth user data to `UserInfo` struct
- **OAuth Configuration** - `OAuthConfig` and `OAuthProvider` structs with validation

#### BFF (Backend-for-Frontend) Architecture

- **BFFAuthOptions** - Configuration for session-based authentication
- **SessionService Interface** - `CreateSession`, `GetSession`, `DeleteSession`, `ValidateSession` (user-implemented)
- **JWTExchangeService** - Session-to-JWT conversion for microservice communication
- **BFFAuthMiddleware** - `RequireSession`, `RequireValidSession`, `OptionalSession` route protection
- **NewBFFAuthService** - Constructor for BFF-only authentication services

#### Cookie Management

- **Manual Cookie Control** - Users explicitly set SID cookies after session creation using Gin's built-in functions
- **Session ID Generation** - Users implement their own session ID generation (example provided)
- **Standard Gin Integration** - Uses `c.SetCookie()` and `c.Cookie()` for cookie management

#### Configuration & Validation

- **AuthOptions Validation** - `ValidateAuthOptions()` with required field checks and defaults
- **BFFAuthOptions Validation** - `ValidateBFFAuthOptions()` with SessionService requirement
- **OAuth Configuration Validation** - `ValidateOAuthConfig()` and `ValidateOAuthProvider()`
- **Default Value Setting** - Automatic defaults for Realm, SameSite, etc.

### Changed

#### Service Architecture

- **Modular AuthService** - Now contains optional `JWT *JWTService`, `BFF *BFFService`, `OAuth *OAuthService`
- **Service Grouping** - Related functionality grouped into dedicated service structs
- **Constructor Specialization** - `NewAuthService()` for JWT+OAuth, `NewBFFAuthService()` for BFF+OAuth

#### API Structure

- **Handler Access** - JWT handlers via `authService.JWT.Middleware.LoginHandler()`
- **BFF Middleware** - Session protection via `authService.BFF.Middleware.RequireSession()`
- **OAuth Handlers** - OAuth flows via `authService.OAuth.BeginAuthHandler()`
- **Service-Specific Methods** - JWT exchange via `authService.BFF.Exchange.ExchangeSessionForJWT()`

#### Configuration Options

- **AuthOptions Extended** - Added `OAuth *OAuthConfig`, `SessionSameSite`, `IdentityKey` fields
- **Session Configuration** - `SessionSecret`, `SessionMaxAge`, `SessionDomain`, `SessionSecure` for OAuth state
- **Interface-Driven Design** - `SessionService` must be provided by implementing projects

#### Token Handling

- **Token Lookup Priority** - Header → Query Parameter → Cookie (clarified in documentation)
- **Multiple Delivery Methods** - Simultaneous support for Authorization header, query param, and cookie
- **Hybrid Support** - Traditional JWT and BFF session patterns in same service

### Removed

#### Deprecated Methods

- **Direct AuthService Handlers** - Removed `LoginHandler()`, `LogoutHandler()`, `RefreshHandler()`, `MiddlewareFunc()`
- **Wrapper Methods** - Eliminated getter methods in favor of direct service access
- **Built-in Session Implementation** - Removed placeholder `SessionService` implementation

#### Interfaces

- **Simplified Interface Design** - Removed `OAuthService`, `SessionExchangeService`, `BFFAuthMiddleware` interfaces in favor of concrete structs

### Fixed

#### Error Handling

- **Configuration Validation** - Clear error messages for missing required fields
- **OAuth Error Handling** - Proper error responses in OAuth flow handlers
- **Session Validation** - Robust session validation with appropriate error codes

#### Security Improvements

- **Cookie Security** - HttpOnly, Secure, and SameSite defaults for all cookies
- **Session ID Generation** - Users implement their own secure session ID generation
- **JWT Security** - Proper JWT validation and signing in exchange service

#### Code Organization

- **File Structure** - Separated concerns into `config.go`, `validation.go`, `oauth.go`, `bff_middleware.go`, etc.
- **Import Organization** - Clean separation of core package and standard library usage
- **Test Coverage** - Comprehensive tests for JWT regression, OAuth foundation, and BFF functionality

### Dependencies

#### New Dependencies

- `github.com/markbates/goth` - OAuth provider support
- `github.com/gorilla/sessions` - Session management for OAuth state
- `github.com/stretchr/testify` - Enhanced testing capabilities

#### Updated Dependencies

- `github.com/golang-jwt/jwt/v4` - JWT handling (indirect dependency)

### Migration Guide

#### From v1.0.1 to v1.0.2

**AuthService Handler Access:**

```go
// Old (v1.0.1)
authService.LoginHandler()
authService.MiddlewareFunc()

// New (v1.0.2)
authService.JWT.Middleware.LoginHandler()
authService.JWT.Middleware.MiddlewareFunc()
```

**Configuration Structure:**

```go
// Old (v1.0.1)
opts := &auth.AuthOptions{
    BcryptCost: 12, // Removed
    // ...
}

// New (v1.0.2)
opts := &auth.AuthOptions{
    // BcryptCost removed - use bcrypt.GenerateFromPassword() directly
    OAuth: &auth.OAuthConfig{
        // OAuth configuration now available
    },
}
```

**BFF Authentication (New):**

```go
// BFF setup requires SessionService implementation
bffOpts := &auth.BFFAuthOptions{
    SessionService: mySessionService, // You must implement this
    // ...
}
bffService, err := auth.NewBFFAuthService(bffOpts)
```

### Breaking Changes

1. **Handler Method Removal** - Direct `AuthService` handler methods removed
2. **BcryptCost Removal** - Configuration field removed, use `bcrypt.GenerateFromPassword([]byte(password), cost)` directly
3. **SessionService Requirement** - BFF mode requires user-provided `SessionService` implementation
4. **Manual Cookie Management** - Users must explicitly set SID cookies after session creation
