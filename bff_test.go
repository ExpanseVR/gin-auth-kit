package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ExpanseVR/gin-auth-kit/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)
type mockSessionServiceImpl struct{}

func (m *mockSessionServiceImpl) CreateSession(user UserInfo, expiry time.Duration) (string, error) {
	return "test_sid", nil
}

func (m *mockSessionServiceImpl) GetSession(sid string) (UserInfo, error) {
	if sid == "" {
		return UserInfo{}, ErrInvalidSession
	}
	return UserInfo{}, ErrSessionNotFound
}

func (m *mockSessionServiceImpl) DeleteSession(sid string) error {
	if sid == "" {
		return ErrInvalidSession
	}
	return nil
}

func (m *mockSessionServiceImpl) ValidateSession(sid string) (UserInfo, error) {
	if sid == "" {
		return UserInfo{}, ErrInvalidSession
	}
	return UserInfo{}, ErrSessionNotFound
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
	jwtExchangeService := NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)

	t.Run("ExchangeSessionForJWT_EmptySID", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session ID")
	})

	t.Run("ExchangeSessionForJWT_InvalidSession", func(t *testing.T) {
		_, err := jwtExchangeService.ExchangeSessionForJWT("invalid-sid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session")
	})

	t.Run("RefreshSessionJWT_EmptySID", func(t *testing.T) {
		_, err := jwtExchangeService.RefreshSessionJWT("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session ID")
	})
}


func TestBFFAuthMiddleware(t *testing.T) {
	mockSessionService := &mockSessionServiceImpl{}
	jwtExchangeService := NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
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
		assert.Contains(t, w.Body.String(), "Invalid session")
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
	})

	t.Run("SetSIDCookie_ValidSID", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		config := CookieConfig{Name: "test_sid", Path: "/"}
		SetSIDCookie(c, "test_sid_value", config)
		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "test_sid", cookies[0].Name)
		assert.Equal(t, "test_sid_value", cookies[0].Value)
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

		ClearSIDCookie(c, "test_sid")
		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "test_sid", cookies[0].Name)
		assert.Equal(t, -1, cookies[0].MaxAge)
	})

	t.Run("SetSecureCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		config := CookieConfig{MaxAge: 3600, Path: "/", HttpOnly: true}
		SetSecureCookie(c, "secure_cookie", "value", config)
		
		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "secure_cookie", cookies[0].Name)
		assert.Equal(t, "value", cookies[0].Value)
		assert.True(t, cookies[0].Secure)
		assert.True(t, cookies[0].HttpOnly)
	})

	t.Run("GetCookie_NoCookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)

		value := GetCookie(c, "nonexistent")
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
		
		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "test_cookie", cookies[0].Name)
		assert.Equal(t, -1, cookies[0].MaxAge)
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


func TestBFFServiceConstructors(t *testing.T) {
	mockSessionService := &mockSessionServiceImpl{}

	t.Run("MockSessionService", func(t *testing.T) {
		assert.NotNil(t, mockSessionService)
	})

	t.Run("NewJWTExchangeService", func(t *testing.T) {
		jwtExchangeService := NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
		assert.NotNil(t, jwtExchangeService)
	})

	t.Run("NewBFFAuthMiddleware", func(t *testing.T) {
		jwtExchangeService := NewJWTExchangeService("test-secret", mockSessionService, time.Minute*10)
		bffMiddleware := NewBFFAuthMiddleware(mockSessionService, jwtExchangeService, "sid")
		assert.NotNil(t, bffMiddleware)
	})
}

func TestBFFAuthOptionsValidation(t *testing.T) {
	t.Run("Valid_BFFAuthOptions", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret: "test-secret",
			SessionMaxAge: 86400,
			JWTSecret:     "jwt-secret",
			JWTExpiry:     10 * time.Minute,
			SessionService: &mockSessionServiceImpl{},
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.NoError(t, err)
	})

	t.Run("Nil_BFFAuthOptions", func(t *testing.T) {
		var opts *BFFAuthOptions
		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("Missing_SessionSecret", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionMaxAge: 86400,
			JWTSecret:     "jwt-secret",
			JWTExpiry:     10 * time.Minute,
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionSecret is required")
	})

	t.Run("Invalid_SessionMaxAge", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret: "test-secret",
			SessionMaxAge: -1,
			JWTSecret:     "jwt-secret",
			JWTExpiry:     10 * time.Minute,
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SessionMaxAge must be positive")
	})

	t.Run("Missing_JWTSecret", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret: "test-secret",
			SessionMaxAge: 86400,
			JWTExpiry:     10 * time.Minute,
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWTSecret is required")
	})

	t.Run("Invalid_JWTExpiry", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret: "test-secret",
			SessionMaxAge: 86400,
			JWTSecret:     "jwt-secret",
			JWTExpiry:     -1 * time.Minute,
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWTExpiry must be positive")
	})

	t.Run("Missing_FindUserByEmail", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret:   "test-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "jwt-secret",
			JWTExpiry:       10 * time.Minute,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByEmail callback is required")
	})

	t.Run("Missing_FindUserByID", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret:   "test-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "jwt-secret",
			JWTExpiry:       10 * time.Minute,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "FindUserByID callback is required")
	})

	t.Run("Default_Cookie_Values", func(t *testing.T) {
		opts := &BFFAuthOptions{
			SessionSecret:   "test-secret",
			SessionMaxAge:   86400,
			JWTSecret:       "jwt-secret",
			JWTExpiry:       10 * time.Minute,
			SessionService:  &mockSessionServiceImpl{},
			FindUserByEmail: func(email string) (UserInfo, error) {
				return UserInfo{}, nil
			},
			FindUserByID: func(id uint) (UserInfo, error) {
				return UserInfo{}, nil
			},
		}

		err := opts.ValidateBFFAuthOptions()
		assert.NoError(t, err)
		assert.Equal(t, "sid", opts.SIDCookieName)
		assert.Equal(t, "/", opts.SIDCookiePath)
	})
} 