package utils

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a bcrypt hash of the password with the given cost
func HashPassword(password string, cost int) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword compares a hashed password with a plaintext password
func VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Debug().Err(err).Msg("Password verification failed")
		return err
	}
	return nil
}

// IsValidPassword checks if password meets security requirements
func IsValidPassword(password string) bool {
	// Minimum length requirement
	if len(password) < 8 {
		return false
	}

	// Maximum length to prevent DoS attacks
	if len(password) > 128 {
		return false
	}

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return false
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return false
	}

	// Check for at least one digit
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasDigit {
		return false
	}

	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password)
	if !hasSpecial {
		return false
	}

	// Check against common weak passwords
	commonPasswords := []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
		"1234567890", "password1", "123123", "admin123",
	}

	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPassword == common {
			return false
		}
	}

	return true
}
