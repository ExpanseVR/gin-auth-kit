# Extensible UserInfo Example

This example demonstrates how to extend the `UserInfo` struct from gin-auth-kit to add custom fields and functionality while maintaining compatibility with the authentication system.

## Overview

The `UserInfo` struct in gin-auth-kit is designed to be extensible. This example shows four different patterns for extending it:

1. **Embedding** - Embed `UserInfo` in a custom struct
2. **CustomFields** - Use the built-in `CustomFields` map
3. **Custom Methods** - Create a custom struct with additional methods
4. **Factory** - Use factory functions to create `UserInfo` with custom fields

## Usage

```bash
cd examples/extensible_user
go run main.go
```

## Patterns Explained

### 1. Embedding

Embed `UserInfo` in your own struct for type-safe extensions:

```go
type ExtendedUser struct {
    auth.UserInfo  // Embed the base UserInfo
    PhoneNumber    string
    DateOfBirth    *time.Time
    // ... additional fields
}
```

### 2. CustomFields

Use the built-in `CustomFields` map for dynamic extensions:

```go
userInfo := auth.UserInfo{
    ID:        1,
    Email:     "john@example.com",
    FirstName: "John",
    LastName:  "Doe",
}
userInfo.SetCustomField("phone_number", "+1234567890")
userInfo.SetCustomField("is_verified", true)
```

### 3. Custom Methods

Create a custom struct with additional methods:

```go
type CustomUserInfo struct {
    auth.UserInfo
}

func (c *CustomUserInfo) GetDisplayName() string {
    if c.GetFullName() != "" {
        return c.GetFullName()
    }
    return c.Email
}
```

### 4. Factory

Use factory functions to create `UserInfo` with custom fields:

```go
userInfo := CreateUserInfo(1, "john@example.com", "user", "John", "Doe", map[string]any{
    "phone_number": "+1234567890",
    "is_verified":  true,
})
```

## JWT Integration

Custom fields are automatically included in JWT tokens:

```json
{
  "user_id": 1,
  "email": "john@example.com",
  "role": "user",
  "first_name": "John",
  "last_name": "Doe",
  "custom_phone_number": "+1234567890",
  "custom_is_verified": true
}
```
