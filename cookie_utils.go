package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     "sid",
		Domain:   "",
		Path:     "/",
		MaxAge:   86400 * 30,
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func SetSIDCookie(c *gin.Context, sid string, config CookieConfig) {
	if sid == "" {
		return
	}

	if config.Name == "" {
		config = DefaultCookieConfig()
	}

	// Set SameSite attribute first
	c.SetSameSite(config.SameSite)

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

func GetSIDCookie(c *gin.Context, cookieName string) string {
	if cookieName == "" {
		cookieName = "sid"
	}

	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return ""
	}

	return cookie
}

func ClearSIDCookie(c *gin.Context, cookieName string) {
	if cookieName == "" {
		cookieName = "sid"
	}

	c.SetCookie(
		cookieName,
		"",
		-1,
		"/",
		"",
		false,
		true,
	)
}

func SetSecureCookie(c *gin.Context, name, value string, config CookieConfig) {
	// Set SameSite attribute first
	c.SetSameSite(config.SameSite)

	c.SetCookie(
		name,
		value,
		config.MaxAge,
		config.Path,
		config.Domain,
		config.Secure,
		config.HttpOnly,
	)
}

func GetCookie(c *gin.Context, name string) string {
	cookie, err := c.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie
}

func ClearCookie(c *gin.Context, name string) {
	c.SetCookie(
		name,
		"",
		-1,
		"/",
		"",
		false,
		true,
	)
}

func ValidateCookieConfig(config CookieConfig) error {
	if config.Name == "" {
		return errors.New("cookie name cannot be empty")
	}
	if config.MaxAge < 0 {
		return errors.New("cookie MaxAge cannot be negative")
	}
	return nil
} 