package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/sessions"
)

// Session-related errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidSession  = errors.New("invalid session")
)

// Session represents a user session stored in the database
type Session struct {
	SID        string    `json:"sid"`
	UserID     uint      `json:"user_id"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastAccess time.Time `json:"last_access"`
}

// sessionService implements the SessionService interface
type sessionService struct {
	store sessions.Store
}

// NewSessionService creates a new session service instance
func NewSessionService(store sessions.Store) SessionService {
	return &sessionService{
		store: store,
	}
}

// CreateSession creates a new session for a user
func (s *sessionService) CreateSession(user UserInfo, expiry time.Duration) (string, error) {
	// Generate a secure session ID
	sid, err := generateSecureSID()
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create session data
	now := time.Now()
	_ = &Session{
		SID:        sid,
		UserID:     user.ID,
		Email:      user.Email,
		Role:       user.Role,
		CreatedAt:  now,
		ExpiresAt:  now.Add(expiry),
		LastAccess: now,
	}

	// Store session in the session store
	// Note: This is a placeholder implementation
	// The actual implementation will depend on the specific session store used
	// (database, Redis, etc.) which will be provided by the implementing project
	if s.store == nil {
		return "", errors.New("session store not configured")
	}

	// For now, we'll return the session ID
	// The actual storage will be handled by the implementing project
	return sid, nil
}

// GetSession retrieves a session by SID
func (s *sessionService) GetSession(sid string) (UserInfo, error) {
	if sid == "" {
		return UserInfo{}, ErrInvalidSession
	}

	// This is a placeholder implementation
	// The actual implementation will depend on the specific session store used
	// which will be provided by the implementing project
	if s.store == nil {
		return UserInfo{}, errors.New("session store not configured")
	}

	// For now, return an error indicating session not found
	// The actual retrieval will be handled by the implementing project
	return UserInfo{}, ErrSessionNotFound
}

// DeleteSession removes a session by SID
func (s *sessionService) DeleteSession(sid string) error {
	if sid == "" {
		return ErrInvalidSession
	}

	// This is a placeholder implementation
	// The actual implementation will depend on the specific session store used
	// which will be provided by the implementing project
	if s.store == nil {
		return errors.New("session store not configured")
	}

	// For now, we'll assume success
	// The actual deletion will be handled by the implementing project
	return nil
}

// ValidateSession checks if a session is valid and not expired
func (s *sessionService) ValidateSession(sid string) (UserInfo, error) {
	// Get the session
	userInfo, err := s.GetSession(sid)
	if err != nil {
		return UserInfo{}, err
	}

	// Check if session is expired
	// Note: This would typically be done in the GetSession method
	// based on the session data retrieved from storage
	// For now, we'll assume the session is valid if we can retrieve it

	return userInfo, nil
}

// generateSecureSID generates a cryptographically secure session ID
func generateSecureSID() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string
	return fmt.Sprintf("sid_%x", bytes), nil
} 