package utils

import (
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

// IsValidPassword checks if password meets minimum requirements
func IsValidPassword(password string) bool {
	// Minimum length requirement
	return len(password) >= 8
}
