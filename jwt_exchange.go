package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrJWTGenerationFailed = errors.New("failed to generate JWT")
	ErrJWTValidationFailed = errors.New("failed to validate JWT")
	ErrInvalidJWTSecret    = errors.New("invalid JWT secret")
	ErrInvalidSession      = errors.New("invalid session")
	ErrInvalidSID          = errors.New("invalid session ID")
)

type JWTExchangeService struct {
	jwtSecret      string
	sessionService SessionService
	jwtExpiry      time.Duration
}

func NewJWTExchangeService(jwtSecret string, sessionService SessionService, jwtExpiry time.Duration) *JWTExchangeService {
	return &JWTExchangeService{
		jwtSecret:      jwtSecret,
		sessionService: sessionService,
		jwtExpiry:      jwtExpiry,
	}
}

func (j *JWTExchangeService) ExchangeSessionForJWT(sid string) (string, error) {
	if sid == "" {
		return "", ErrInvalidSID
	}

	userInfo, err := j.sessionService.ValidateSession(sid)
	if err != nil {
		return "", ErrInvalidSession
	}

	token, err := j.generateJWT(userInfo)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}

func (j *JWTExchangeService) RefreshSessionJWT(sid string) (string, error) {
	if sid == "" {
		return "", ErrInvalidSID
	}

	userInfo, err := j.sessionService.ValidateSession(sid)
	if err != nil {
		return "", ErrInvalidSession
	}

	token, err := j.generateJWT(userInfo)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}

func (j *JWTExchangeService) generateJWT(user UserInfo) (string, error) {
	if j.jwtSecret == "" {
		return "", ErrInvalidJWTSecret
	}

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(j.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

func (j *JWTExchangeService) validateJWT(tokenString string) (UserInfo, error) {
	if j.jwtSecret == "" {
		return UserInfo{}, ErrInvalidJWTSecret
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(j.jwtSecret), nil
	})

	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return UserInfo{}, ErrJWTValidationFailed
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return UserInfo{}, ErrJWTValidationFailed
	}

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