package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/ExpanseVR/gin-auth-kit/types"
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
	sessionService types.SessionService
	jwtExpiry      time.Duration
}

func NewJWTExchangeService(jwtSecret string, sessionService types.SessionService, jwtExpiry time.Duration) *JWTExchangeService {
	return &JWTExchangeService{
		jwtSecret:      jwtSecret,
		sessionService: sessionService,
		jwtExpiry:      jwtExpiry,
	}
}

func (exchangeService *JWTExchangeService) ExchangeSessionForJWT(sid string) (string, error) {
	if sid == "" {
		return "", ErrInvalidSID
	}

	userInfo, err := exchangeService.sessionService.ValidateSession(sid)
	if err != nil {
		return "", ErrInvalidSession
	}

	token, err := exchangeService.generateJWT(userInfo)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}

func (exchangeService *JWTExchangeService) RefreshSessionJWT(sid string) (string, error) {
	if sid == "" {
		return "", ErrInvalidSID
	}

	userInfo, err := exchangeService.sessionService.ValidateSession(sid)
	if err != nil {
		return "", ErrInvalidSession
	}

	token, err := exchangeService.generateJWT(userInfo)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}

func (exchangeService *JWTExchangeService) generateJWT(user types.UserInfo) (string, error) {
	if exchangeService.jwtSecret == "" {
		return "", ErrInvalidJWTSecret
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"iat":     now.Unix(),
		"exp":     now.Add(exchangeService.jwtExpiry).Unix(),
		"iss":     "gin-auth-kit",
		"aud":     "api",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(exchangeService.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}
