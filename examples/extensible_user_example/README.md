# Extensible UserInfo Example

This example demonstrates how to extend the `UserInfo` struct from gin-auth-kit to add custom fields and functionality while maintaining compatibility with the authentication system.

## Overview

The `UserInfo` struct in gin-auth-kit is designed to be extensible. This example shows four different patterns for extending it:

1. **Embedding** - Embed `UserInfo` in a custom struct
2. **CustomFields** - Use the built-in `CustomFields` map
3. **Custom Methods** - Create a custom struct with additional methods
4. **Factory** - Use factory functions to create `UserInfo` with custom fields

## OAuth Integration

When users sign in via OAuth (Google, GitHub, Facebook, etc.), the system automatically populates `CustomFields` with fresh data from the OAuth provider:

### **Automatic OAuth Data Injection**

```go
// OAuth providers automatically inject these fields into CustomFields:
userInfo.CustomFields = map[string]any{
    "goth_name":    "Dr. John A. Doe Jr.",    // Original name from OAuth provider
    "nickname":     "johndoe",                 // Username/nickname from OAuth provider
    "avatar_url":   "https://google.com/avatar.jpg", // Profile picture URL
    "location":     "San Francisco, CA",       // User's location
    "description":  "Software developer",      // User's bio/description
}
```

### **Key Benefits of OAuth Data**

1. **Fresh Data**: OAuth data is always current (updated on each login)
2. **Original Names**: Access the original name format from OAuth provider
3. **Profile Pictures**: Automatic avatar URLs from OAuth providers
4. **Additional Info**: Location, bio, nickname, etc.

### **Accessing OAuth Data**

```go
// Get the original name from OAuth provider
if gothName, exists := userInfo.GetCustomField("goth_name"); exists {
    fmt.Printf("Original OAuth name: %v\n", gothName)
}

// Get profile picture
if avatarURL, exists := userInfo.GetCustomField("avatar_url"); exists {
    fmt.Printf("Profile picture: %v\n", avatarURL)
}

// Get user's location
if location, exists := userInfo.GetCustomField("location"); exists {
    fmt.Printf("User location: %v\n", location)
}
```

### **Name Handling Strategy**

The system provides **both parsed and original names**:

```go
// Parsed names (from FirstName/LastName fields)
firstName := userInfo.FirstName  // "Dr."
lastName := userInfo.LastName    // "John A. Doe Jr."

// Original name (from CustomFields)
if gothName, exists := userInfo.GetCustomField("goth_name"); exists {
    originalName := gothName.(string)  // "Dr. John A. Doe Jr."
}
```

This gives you flexibility to use either the parsed names or the original OAuth provider format.

### **Practical Example: OAuth + Custom Fields**

```go
// Example: User signs in via Google OAuth
// The system automatically populates CustomFields with Google data
userInfo := auth.UserInfo{
    ID:        123,
    Email:     "john.doe@gmail.com",
    Role:      "user",
    FirstName: "John",           // Parsed from Google's name
    LastName:  "Doe",            // Parsed from Google's name
    CustomFields: map[string]any{
        "goth_name":    "John Doe",                    // Original Google name
        "avatar_url":   "https://google.com/avatar.jpg", // Google profile picture
        "location":     "San Francisco, CA",           // Google location
        "phone_number": "+1234567890",                 // Your app's custom field
        "is_verified":  true,                          // Your app's custom field
    },
}

// You can access both OAuth data and your custom data
if avatarURL, exists := userInfo.GetCustomField("avatar_url"); exists {
    // Use Google's profile picture
    displayAvatar(avatarURL.(string))
}

if phoneNumber, exists := userInfo.GetCustomField("phone_number"); exists {
    // Use your app's phone number field
    displayPhone(phoneNumber.(string))
}
```

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

Custom fields are automatically included in JWT tokens (including OAuth data):

```json
{
  "user_id": 1,
  "email": "john@example.com",
  "role": "user",
  "first_name": "John",
  "last_name": "Doe",
  "custom_phone_number": "+1234567890",
  "custom_is_verified": true,
  "custom_goth_name": "John Doe",
  "custom_avatar_url": "https://google.com/avatar.jpg",
  "custom_location": "San Francisco, CA"
}
```

**Note**: All custom fields (including OAuth data) are prefixed with `custom_` in JWT tokens for security and clarity.
