package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
)

// Mock session store for testing
type mockSessionStore struct {
	sessions map[string]*Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(m, name), nil
}

func (m *mockSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.NewSession(m, name), nil
}

func (m *mockSessionStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	return nil
}

// TestSessionService tests the session service functionality
func TestSessionService(t *testing.T) {
	mockStore := newMockSessionStore()
	sessionService := NewSessionService(mockStore)

	user := UserInfo{
		ID:    1,
		Email: "test@example.com",
		Role:  "customer",
	}

	t.Run("CreateSession", func(t *testing.T) {
		sid, err := sessionService.CreateSession(user, 30*time.Minute)
		assert.NoError(t, err)
		assert.NotEmpty(t, sid)
		assert.Contains(t, sid, "sid_")
	})

	t.Run("GetSession_EmptySID", func(t *testing.T) {
		_, err := sessionService.GetSession("")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSession, err)
	})

	t.Run("GetSession_NotFound", func(t *testing.T) {
		_, err := sessionService.GetSession("sid_nonexistent")
		assert.Error(t, err)
		assert.Equal(t, ErrSessionNotFound, err)
	})

	t.Run("DeleteSession_EmptySID", func(t *testing.T) {
		err := sessionService.DeleteSession("")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSession, err)
	})

	t.Run("DeleteSession_Success", func(t *testing.T) {
		err := sessionService.DeleteSession("sid_test")
		assert.NoError(t, err)
	})

	t.Run("ValidateSession_EmptySID", func(t *testing.T) {
		_, err := sessionService.ValidateSession("")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSession, err)
	})
}

// TestJWTExchangeService tests the JWT exchange service functionality
func TestJWTExchangeService(t *testing.T) {
	mockStore := newMockSessionStore()
	sessionService := NewSessionService(mockStore)
	jwtExchangeService := NewJWTExchangeService("test-secret", sessionService, 10*time.Minute)

	t.Run("ExchangeSessionForJWT_EmptySID", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSession, err)
	})

	t.Run("ExchangeSessionForJWT_InvalidSession", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("sid_invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})

	t.Run("RefreshSessionJWT_EmptySID", func(t *testing.T) {
		_, err := jwtExchangeService.RefreshSessionJWT("")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSession, err)
	})
}

// TestBFFAuthMiddleware tests the BFF auth middleware functionality
func TestBFFAuthMiddleware(t *testing.T) {
	mockStore := newMockSessionStore()
	sessionService := NewSessionService(mockStore)
	jwtExchangeService := NewJWTExchangeService("test-secret", sessionService, 10*time.Minute)
	bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, "sid")

	gin.SetMode(gin.TestMode)

	t.Run("RequireSession_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		handler := bffMiddleware.RequireSession()
		handler(c)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Session required")
	})

	t.Run("RequireSession_InvalidSession", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.AddCookie(&http.Cookie{Name: "sid", Value: "invalid_sid"})

		handler := bffMiddleware.RequireSession()
		handler(c)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid session")
	})

	t.Run("OptionalSession_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		handler := bffMiddleware.OptionalSession()
		handler(c)

		assert.Equal(t, http.StatusOK, w.Code) // Should continue without error
	})

	t.Run("OptionalSession_InvalidSession", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.AddCookie(&http.Cookie{Name: "sid", Value: "invalid_sid"})

		handler := bffMiddleware.OptionalSession()
		handler(c)

		assert.Equal(t, http.StatusOK, w.Code) // Should continue without error
	})
}

// TestCookieUtils tests the cookie utility functions
func TestCookieUtils(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("DefaultCookieConfig", func(t *testing.T) {
		config := DefaultCookieConfig()
		assert.Equal(t, "sid", config.Name)
		assert.Equal(t, "/", config.Path)
		assert.Equal(t, 86400*30, config.MaxAge)
		assert.False(t, config.Secure)
		assert.True(t, config.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, config.SameSite)
	})

	t.Run("SetSIDCookie_EmptySID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		SetSIDCookie(c, "", CookieConfig{})
		// Should not panic or error
	})

	t.Run("SetSIDCookie_ValidSID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		SetSIDCookie(c, "test_sid", CookieConfig{Name: "sid"})
		// Should not panic or error
	})

	t.Run("GetSIDCookie_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		sid := GetSIDCookie(c, "sid")
		assert.Empty(t, sid)
	})

	t.Run("GetSIDCookie_WithCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.AddCookie(&http.Cookie{Name: "sid", Value: "test_sid"})

		sid := GetSIDCookie(c, "sid")
		assert.Equal(t, "test_sid", sid)
	})

	t.Run("GetSIDCookie_DefaultName", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.AddCookie(&http.Cookie{Name: "sid", Value: "test_sid"})

		sid := GetSIDCookie(c, "")
		assert.Equal(t, "test_sid", sid)
	})

	t.Run("ClearSIDCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		ClearSIDCookie(c, CookieConfig{Name: "sid"})
		// Should not panic or error
	})

	t.Run("SetSecureCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		SetSecureCookie(c, "secure_cookie", "value", 3600)
		// Should not panic or error
	})

	t.Run("GetCookie_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		value := GetCookie(c, "test_cookie")
		assert.Empty(t, value)
	})

	t.Run("GetCookie_WithCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.AddCookie(&http.Cookie{Name: "test_cookie", Value: "test_value"})

		value := GetCookie(c, "test_cookie")
		assert.Equal(t, "test_value", value)
	})

	t.Run("ClearCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		ClearCookie(c, "test_cookie")
		// Should not panic or error
	})

	t.Run("ValidateCookieConfig_Valid", func(t *testing.T) {
		config := CookieConfig{Name: "test", MaxAge: 3600}
		err := ValidateCookieConfig(config)
		assert.NoError(t, err)
	})

	t.Run("ValidateCookieConfig_EmptyName", func(t *testing.T) {
		config := CookieConfig{Name: "", MaxAge: 3600}
		err := ValidateCookieConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cookie name is required")
	})

	t.Run("ValidateCookieConfig_NegativeMaxAge", func(t *testing.T) {
		config := CookieConfig{Name: "test", MaxAge: -1}
		err := ValidateCookieConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cookie max age must be non-negative")
	})
}

// TestBFFServiceConstructors tests the constructor functions
func TestBFFServiceConstructors(t *testing.T) {
	mockStore := newMockSessionStore()

	t.Run("NewSessionService", func(t *testing.T) {
		sessionService := NewSessionService(mockStore)
		assert.NotNil(t, sessionService)
	})

	t.Run("NewJWTExchangeService", func(t *testing.T) {
		sessionService := NewSessionService(mockStore)
		jwtExchangeService := NewJWTExchangeService("test-secret", sessionService, 10*time.Minute)
		assert.NotNil(t, jwtExchangeService)
	})

	t.Run("NewBFFAuthMiddleware", func(t *testing.T) {
		sessionService := NewSessionService(mockStore)
		jwtExchangeService := NewJWTExchangeService("test-secret", sessionService, 10*time.Minute)
		bffMiddleware := NewBFFAuthMiddleware(sessionService, jwtExchangeService, "sid")
		assert.NotNil(t, bffMiddleware)
	})
} 