package bff

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gak_jwt "github.com/ExpanseVR/gin-auth-kit/jwt"
	"github.com/ExpanseVR/gin-auth-kit/types"
	"github.com/ExpanseVR/gin-auth-kit/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

func mockFindUserByEmail(email string) (types.UserInfo, error) {
	if email == "test@example.com" {
		return types.UserInfo{
			ID:    1,
			Email: email,
			Role:  "user",
		}, nil
	}
	return types.UserInfo{}, errors.New("user not found")
}

func mockFindUserByID(id uint) (types.UserInfo, error) {
	if id == 1 {
		return types.UserInfo{
			ID:    id,
			Email: "test@example.com",
			Role:  "user",
		}, nil
	}
	return types.UserInfo{}, errors.New("user not found")
}

type mockSessionServiceImpl struct{}

func (m *mockSessionServiceImpl) CreateSession(user types.UserInfo, expiry time.Duration) (string, error) {
	return "test_sid", nil
}

func (m *mockSessionServiceImpl) GetSession(sid string) (types.UserInfo, error) {
	if sid == "" {
		return types.UserInfo{}, gak_jwt.ErrInvalidSession
	}
	return types.UserInfo{}, ErrSessionNotFound
}

func (m *mockSessionServiceImpl) DeleteSession(sid string) error {
	if sid == "" {
		return gak_jwt.ErrInvalidSession
	}
	return nil
}

func (m *mockSessionServiceImpl) ValidateSession(sid string) (types.UserInfo, error) {
	if sid == "" {
		return types.UserInfo{}, gak_jwt.ErrInvalidSession
	}
	return types.UserInfo{}, ErrSessionNotFound
}

func TestSessionService(t *testing.T) {
	t.Skip("SessionService is now an interface - users must provide their own implementation")
}
func TestGenerateSecureSID(t *testing.T) {
	t.Run("GeneratesValidSID", func(t *testing.T) {
		sid, err := utils.GenerateSecureSID()

		assert.NoError(t, err)
		assert.NotEmpty(t, sid)
		assert.True(t, len(sid) > 60)
		assert.Contains(t, sid, "sid_")
	})

	t.Run("GeneratesUniqueSIDs", func(t *testing.T) {
		sid1, err1 := utils.GenerateSecureSID()
		sid2, err2 := utils.GenerateSecureSID()

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, sid1, sid2)
	})

	t.Run("ConsistentFormat", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			sid, err := utils.GenerateSecureSID()
			assert.NoError(t, err)
			assert.Regexp(t, `^sid_[a-f0-9]{64}$`, sid)
		}
	})
}

func TestJWTExchangeService(t *testing.T) {
	mockSessionService := &mockSessionServiceImpl{}
	jwtExchangeService := gak_jwt.NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)

	t.Run("ExchangeSessionForJWT_EmptySID", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session ID")
	})

	t.Run("ExchangeSessionForJWT_InvalidSession", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("invalid-sid")
		assert.Error(t, err)
	})
}

func TestBFFAuthMiddleware(t *testing.T) {
	mockSessionService := &mockSessionServiceImpl{}
	jwtExchangeService := gak_jwt.NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
	bffMiddleware := NewBFFAuthMiddleware(mockSessionService, jwtExchangeService, "sid")

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
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "sid", Value: "invalid-sid"})
		c.Request = req

		handler := bffMiddleware.RequireSession()
		handler(c)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Session required")
	})

	t.Run("OptionalSession_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		handler := bffMiddleware.OptionalSession()
		handler(c)

		_, exists := c.Get("user")
		assert.False(t, exists)
	})

	t.Run("OptionalSession_InvalidSession", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{Name: "sid", Value: "invalid-sid"})
		c.Request = req

		handler := bffMiddleware.OptionalSession()
		handler(c)

		_, exists := c.Get("user")
		assert.False(t, exists)
	})
}

func TestBFFServiceConstructors(t *testing.T) {
	mockSessionService := &mockSessionServiceImpl{}

	t.Run("MockSessionService", func(t *testing.T) {
		assert.NotNil(t, mockSessionService)
	})

	t.Run("NewJWTExchangeService", func(t *testing.T) {
		jwtExchangeService := gak_jwt.NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
		assert.NotNil(t, jwtExchangeService)
	})

	t.Run("NewBFFAuthMiddleware", func(t *testing.T) {
		jwtExchangeService := gak_jwt.NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
		bffMiddleware := NewBFFAuthMiddleware(mockSessionService, jwtExchangeService, "sid")
		assert.NotNil(t, bffMiddleware)
	})
}

func TestBFFAuthOptionsValidation(t *testing.T) {
	t.Run("Valid_BFFAuthOptions", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       time.Hour,
			SIDCookieName:   "sid",
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.NoError(t, err)
	})

	t.Run("Nil_BFFAuthOptions", func(t *testing.T) {
		var opts *types.BFFAuthOptions
		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BFFAuthOptions cannot be nil")
	})

	t.Run("Missing_SessionSecret", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionMaxAge:   86400,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       time.Hour,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionSecret is required")
	})

	t.Run("Invalid_SessionMaxAge", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   0,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       time.Hour,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionMaxAge must be positive")
	})

	t.Run("Missing_JWTSecret", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   86400,
			JWTExpiry:       time.Hour,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWTSecret is required")
	})

	t.Run("Invalid_JWTExpiry", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       0,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWTExpiry must be positive")
	})

	t.Run("Missing_SessionService", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       time.Hour,
			FindUserByEmail: mockFindUserByEmail,
			FindUserByID:    mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionService is required")
	})

	t.Run("Missing_FindUserByEmail", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:  "test-session-secret",
			SessionMaxAge:  86400,
			JWTSecret:      "test-jwt-secret",
			JWTExpiry:      time.Hour,
			SessionService: &mockSessionServiceImpl{},
			FindUserByID:   mockFindUserByID,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByEmail callback is required")
	})

	t.Run("Missing_FindUserByID", func(t *testing.T) {
		opts := &types.BFFAuthOptions{
			SessionSecret:   "test-session-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "test-jwt-secret",
			JWTExpiry:       time.Hour,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: mockFindUserByEmail,
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByID callback is required")
	})
}
