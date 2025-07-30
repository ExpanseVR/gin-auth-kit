package utils

import (
	"crypto/rand"
	"fmt"
)

// GenerateSecureSID returns a session ID in the format: "sid_<64-character-hex-string>"
// Example: "sid_a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
func GenerateSecureSID() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return fmt.Sprintf("sid_%x", bytes), nil
} 