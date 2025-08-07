package types

// UserInfo represents user data returned by callback functions
// This struct is extensible - It can be embedded in other structs
// or use the CustomFields map for additional data
type UserInfo struct {
	ID           uint           `json:"id"`
	Email        string         `json:"email"`
	Role         string         `json:"role"`
	FirstName    string         `json:"first_name,omitempty"`
	LastName     string         `json:"last_name,omitempty"`
	PasswordHash string         `json:"-"`                       // Never expose password hash in JSON
	CustomFields map[string]any `json:"custom_fields,omitempty"` // Extensible fields for implementers
}

// GetFullName returns the user's full name
func (userInfo *UserInfo) GetFullName() string {
	if userInfo.FirstName == "" && userInfo.LastName == "" {
		return ""
	}
	if userInfo.FirstName == "" {
		return userInfo.LastName
	}
	if userInfo.LastName == "" {
		return userInfo.FirstName
	}
	return userInfo.FirstName + " " + userInfo.LastName
}

// SetCustomField sets a custom field value
func (userInfo *UserInfo) SetCustomField(key string, value any) {
	if userInfo.CustomFields == nil {
		userInfo.CustomFields = make(map[string]any)
	}
	userInfo.CustomFields[key] = value
}

// GetCustomField retrieves a custom field value
func (userInfo *UserInfo) GetCustomField(key string) (any, bool) {
	if userInfo.CustomFields == nil {
		return nil, false
	}
	value, exists := userInfo.CustomFields[key]
	return value, exists
}
