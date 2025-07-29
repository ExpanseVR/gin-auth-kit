package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CookieConfig represents configuration for SID cookies
type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// DefaultCookieConfig returns a default cookie configuration
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     "sid",
		Domain:   "",
		Path:     "/",
		MaxAge:   86400 * 30, // 30 days
		Secure:   false,      // Set to true in production with HTTPS
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// SetSIDCookie sets a secure SID cookie in the response
func SetSIDCookie(c *gin.Context, sid string, config CookieConfig) {
	if sid == "" {
		return
	}

	// Use default config if not provided
	if config.Name == "" {
		config = DefaultCookieConfig()
	}

	// Set cookie options
	c.SetCookie(
		config.Name,
		sid,
		config.MaxAge,
		config.Path,
		config.Domain,
		config.Secure,
		config.HttpOnly,
	)
}

// GetSIDCookie retrieves the SID from the request cookies
func GetSIDCookie(c *gin.Context, cookieName string) string {
	if cookieName == "" {
		cookieName = "sid" // Default cookie name
	}

	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return ""
	}

	return cookie
}

// ClearSIDCookie removes the SID cookie from the response
func ClearSIDCookie(c *gin.Context, config CookieConfig) {
	// Use default config if not provided
	if config.Name == "" {
		config = DefaultCookieConfig()
	}

	// Set cookie with past expiration to clear it
	c.SetCookie(
		config.Name,
		"",
		-1, // Expire immediately
		config.Path,
		config.Domain,
		config.Secure,
		config.HttpOnly,
	)
}

// SetSecureCookie sets a cookie with secure defaults
func SetSecureCookie(c *gin.Context, name, value string, maxAge int) {
	c.SetCookie(
		name,
		value,
		maxAge,
		"/",
		"",
		true,  // Secure
		true,  // HttpOnly
	)
}

// GetCookie retrieves a cookie value by name
func GetCookie(c *gin.Context, name string) string {
	cookie, err := c.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie
}

// ClearCookie removes a cookie by name
func ClearCookie(c *gin.Context, name string) {
	c.SetCookie(
		name,
		"",
		-1, // Expire immediately
		"/",
		"",
		false,
		true,
	)
}

// ValidateCookieConfig validates cookie configuration
func ValidateCookieConfig(config CookieConfig) error {
	if config.Name == "" {
		return errors.New("cookie name is required")
	}

	if config.MaxAge < 0 {
		return errors.New("cookie max age must be non-negative")
	}

	return nil
} 