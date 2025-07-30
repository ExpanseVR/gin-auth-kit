package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JWT exchange-related errors
var (
	ErrJWTGenerationFailed = errors.New("failed to generate JWT")
	ErrJWTValidationFailed = errors.New("failed to validate JWT")
	ErrInvalidJWTSecret    = errors.New("invalid JWT secret")
	ErrInvalidSession      = errors.New("invalid session")
)

// jwtExchangeService implements the SessionExchangeService interface
type jwtExchangeService struct {
	jwtSecret     string
	sessionService SessionService
	jwtExpiry     time.Duration
}

// NewJWTExchangeService creates a new JWT exchange service instance
func NewJWTExchangeService(jwtSecret string, sessionService SessionService, jwtExpiry time.Duration) SessionExchangeService {
	return &jwtExchangeService{
		jwtSecret:      jwtSecret,
		sessionService: sessionService,
		jwtExpiry:      jwtExpiry,
	}
}

// ExchangeSessionForJWT exchanges a session ID for a JWT token
func (j *jwtExchangeService) ExchangeSessionForJWT(sid string) (string, error) {
	if sid == "" {
		return "", ErrInvalidSession
	}

	// Validate the session and get user info
	userInfo, err := j.sessionService.ValidateSession(sid)
	if err != nil {
		return "", fmt.Errorf("session validation failed: %w", err)
	}

	// Generate JWT token
	token, err := j.generateJWT(userInfo)
	if err != nil {
		return "", fmt.Errorf("JWT generation failed: %w", err)
	}

	return token, nil
}

// RefreshSessionJWT refreshes a JWT token using the session ID
func (j *jwtExchangeService) RefreshSessionJWT(sid string) (string, error) {
	// This is essentially the same as ExchangeSessionForJWT
	// but could be extended to handle refresh token logic in the future
	return j.ExchangeSessionForJWT(sid)
}

// generateJWT creates a new JWT token for the given user
func (j *jwtExchangeService) generateJWT(user UserInfo) (string, error) {
	if j.jwtSecret == "" {
		return "", ErrInvalidJWTSecret
	}

	// Create JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"iat":     now.Unix(),
		"exp":     now.Add(j.jwtExpiry).Unix(),
		"iss":     "gin-auth-kit",
		"aud":     "api",
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	tokenString, err := token.SignedString([]byte(j.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// validateJWT validates and parses a JWT token
func (j *jwtExchangeService) validateJWT(tokenString string) (UserInfo, error) {
	if j.jwtSecret == "" {
		return UserInfo{}, ErrInvalidJWTSecret
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.jwtSecret), nil
	})

	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Validate the token
	if !token.Valid {
		return UserInfo{}, ErrJWTValidationFailed
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return UserInfo{}, ErrJWTValidationFailed
	}

	// Extract user info from claims
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return UserInfo{}, ErrJWTValidationFailed
	}

	email, ok := claims["email"].(string)
	if !ok {
		return UserInfo{}, ErrJWTValidationFailed
	}

	role, ok := claims["role"].(string)
	if !ok {
		return UserInfo{}, ErrJWTValidationFailed
	}

	return UserInfo{
		ID:    uint(userID),
		Email: email,
		Role:  role,
	}, nil
} 