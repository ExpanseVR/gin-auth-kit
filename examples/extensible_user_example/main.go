package main

import (
	"fmt"
	"time"

	"github.com/ExpanseVR/gin-auth-kit/types"
)

// Example 1: Embedding UserInfo in a custom struct
type ExtendedUser struct {
	types.UserInfo                    // Embed the base UserInfo
	PhoneNumber    string            `json:"phone_number"`
	DateOfBirth    *time.Time        `json:"date_of_birth"`
	ProfilePicture string            `json:"profile_picture"`
	Preferences    map[string]bool   `json:"preferences"`
	Metadata       map[string]string `json:"metadata"`
}

// ToUserInfo converts ExtendedUser to auth.UserInfo
func (extendedUser *ExtendedUser) ToUserInfo() types.UserInfo {
	userInfo := extendedUser.UserInfo

	// Add custom fields
	userInfo.SetCustomField("phone_number", extendedUser.PhoneNumber)
	userInfo.SetCustomField("date_of_birth", extendedUser.DateOfBirth)
	userInfo.SetCustomField("profile_picture", extendedUser.ProfilePicture)
	userInfo.SetCustomField("preferences", extendedUser.Preferences)
	userInfo.SetCustomField("metadata", extendedUser.Metadata)

	return userInfo
}

// FromUserInfo creates ExtendedUser from auth.UserInfo
func FromUserInfo(userInfo types.UserInfo) *ExtendedUser {
	extendedUser := &ExtendedUser{
		UserInfo: userInfo,
	}

	// Extract custom fields
	if phone, exists := userInfo.GetCustomField("phone_number"); exists {
		if phoneStr, ok := phone.(string); ok {
			extendedUser.PhoneNumber = phoneStr
		}
	}

	if dob, exists := userInfo.GetCustomField("date_of_birth"); exists {
		if dobTime, ok := dob.(*time.Time); ok {
			extendedUser.DateOfBirth = dobTime
		}
	}

	if picture, exists := userInfo.GetCustomField("profile_picture"); exists {
		if pictureStr, ok := picture.(string); ok {
			extendedUser.ProfilePicture = pictureStr
		}
	}

	if prefs, exists := userInfo.GetCustomField("preferences"); exists {
		if prefsMap, ok := prefs.(map[string]bool); ok {
			extendedUser.Preferences = prefsMap
		}
	}

	if metadata, exists := userInfo.GetCustomField("metadata"); exists {
		if metadataMap, ok := metadata.(map[string]string); ok {
			extendedUser.Metadata = metadataMap
		}
	}

	return extendedUser
}

// Example 2: Using CustomFields directly
type SimpleUserService struct {
	// In a real implementation, this would have a database connection etc.
	users map[string]types.UserInfo
}

func NewSimpleUserService() *SimpleUserService {
	return &SimpleUserService{
		users: make(map[string]types.UserInfo),
	}
}

func (simpleUserService *SimpleUserService) FindUserByEmail(email string) (types.UserInfo, error) {
	user, exists := simpleUserService.users[email]
	if !exists {
		return types.UserInfo{}, fmt.Errorf("user not found")
	}
	return user, nil
}

func (simpleUserService *SimpleUserService) FindUserByID(id uint) (types.UserInfo, error) {
	for _, user := range simpleUserService.users {
		if user.ID == id {
			return user, nil
		}
	}
	return types.UserInfo{}, fmt.Errorf("user not found")
}

// Example 3: Custom UserInfo with additional methods
type CustomUserInfo struct {
	types.UserInfo
}

// NewCustomUserInfo creates a new CustomUserInfo
func NewCustomUserInfo(id uint, email, role, firstName, lastName string) *CustomUserInfo {
	return &CustomUserInfo{
		UserInfo: types.UserInfo{
			ID:        id,
			Email:     email,
			Role:      role,
			FirstName: firstName,
			LastName:  lastName,
		},
	}
}

// GetDisplayName returns a display name for the user
func (customUserInfo *CustomUserInfo) GetDisplayName() string {
	if customUserInfo.GetFullName() != "" {
		return customUserInfo.GetFullName()
	}
	return customUserInfo.Email
}

// IsAdmin checks if the user is an admin
func (customUserInfo *CustomUserInfo) IsAdmin() bool {
	return customUserInfo.Role == "admin"
}

// IsVerified checks if the user is verified
func (customUserInfo *CustomUserInfo) IsVerified() bool {
	if verified, exists := customUserInfo.GetCustomField("is_verified"); exists {
		if isVerified, ok := verified.(bool); ok {
			return isVerified
		}
	}
	return false
}

// GetPhoneNumber returns the user's phone number
func (customUserInfo *CustomUserInfo) GetPhoneNumber() string {
	if phone, exists := customUserInfo.GetCustomField("phone_number"); exists {
		if phoneStr, ok := phone.(string); ok {
			return phoneStr
		}
	}
	return ""
}

// Example 4: Factory function for creating UserInfo with custom fields
func CreateUserInfo(id uint, email, role, firstName, lastName string, customFields map[string]any) types.UserInfo {
	userInfo := types.UserInfo{
		ID:           id,
		Email:        email,
		Role:         role,
		FirstName:    firstName,
		LastName:     lastName,
		CustomFields: customFields,
	}
	return userInfo
}

// Example usage
func main() {
	fmt.Println("=== Extensible UserInfo Example ===\n")

	// Example 1: Using ExtendedUser
	fmt.Println("1. Embedding Pattern:")
	extendedUser := &ExtendedUser{
		UserInfo: types.UserInfo{
			ID:        1,
			Email:     "john.doe@example.com",
			Role:      "user",
			FirstName: "John",
			LastName:  "Doe",
		},
		PhoneNumber: "+1234567890",
		Preferences: map[string]bool{
			"email_notifications": true,
			"sms_notifications":   false,
		},
		Metadata: map[string]string{
			"source": "web_registration",
		},
	}

	// Convert to UserInfo for auth kit
	userInfo := extendedUser.ToUserInfo()
	fmt.Printf("   ExtendedUser converted to UserInfo: %+v\n", userInfo)

	// Example 2: Using CustomFields directly
	fmt.Println("\n2. CustomFields Pattern:")
	simpleUser := types.UserInfo{
		ID:        2,
		Email:     "jane.smith@example.com",
		Role:      "admin",
		FirstName: "Jane",
		LastName:  "Smith",
	}
	simpleUser.SetCustomField("phone_number", "+0987654321")
	simpleUser.SetCustomField("is_verified", true)
	simpleUser.SetCustomField("last_login", time.Now())

	fmt.Printf("   Simple User: %+v\n", simpleUser)
	fmt.Printf("   Full Name: %s\n", simpleUser.GetFullName())
	if phone, exists := simpleUser.GetCustomField("phone_number"); exists {
		if phoneStr, ok := phone.(string); ok {
			fmt.Printf("   Phone: %s\n", phoneStr)
		}
	}

	// Example 3: Using CustomUserInfo
	fmt.Println("\n3. Custom Methods Pattern:")
	customUser := NewCustomUserInfo(3, "bob@example.com", "user", "Bob", "Johnson")
	customUser.SetCustomField("phone_number", "+1122334455")
	customUser.SetCustomField("is_verified", false)

	fmt.Printf("   Custom User: %+v\n", customUser)
	fmt.Printf("   Display Name: %s\n", customUser.GetDisplayName())
	fmt.Printf("   Is Admin: %t\n", customUser.IsAdmin())
	fmt.Printf("   Is Verified: %t\n", customUser.IsVerified())
	fmt.Printf("   Phone: %s\n", customUser.GetPhoneNumber())

	// Example 4: Using factory function
	fmt.Println("\n4. Factory Pattern:")
	factoryUser := CreateUserInfo(4, "alice@example.com", "user", "Alice", "Brown", map[string]any{
		"phone_number": "+1555666777",
		"is_verified":  true,
		"preferences": map[string]bool{
			"newsletter": true,
		},
	})

	fmt.Printf("   Factory User: %+v\n", factoryUser)

	fmt.Println("\n=== Example Complete ===")
}
