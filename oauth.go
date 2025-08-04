package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

var (
	ErrProviderNotFound = errors.New("oauth provider not found")
	ErrNotImplemented   = errors.New("oauth feature not implemented yet")
	ErrInvalidProvider  = errors.New("invalid oauth provider configuration")
	ErrUnsupportedProvider = errors.New("unsupported oauth provider")
	ErrUserNotFound     = errors.New("user not found")
)

func validateProvider(name string, provider OAuthProvider) error {
	if provider.ClientID == "" {
		return fmt.Errorf("%s: ClientID is required", name)
	}
	if provider.ClientSecret == "" {
		return fmt.Errorf("%s: ClientSecret is required", name)
	}
	if provider.RedirectURL == "" {
		return fmt.Errorf("%s: RedirectURL is required", name)
	}
	
	// Validate redirect URL format
	if _, err := url.Parse(provider.RedirectURL); err != nil {
		return fmt.Errorf("%s: RedirectURL must be a valid URL: %v", name, err)
	}
	
	if len(provider.Scopes) > 0 {
		for i, scope := range provider.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("%s: scope %d cannot be empty", name, i)
			}
		}
	}
	
	return nil
}

func createGothProvider(name string, provider OAuthProvider) (goth.Provider, error) {
	if err := validateProvider(name, provider); err != nil {
		return nil, err
	}
	
	switch strings.ToLower(name) {
	case "google":
		return google.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	case "github":
		return github.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	case "facebook":
		return facebook.New(provider.ClientID, provider.ClientSecret, provider.RedirectURL, provider.Scopes...), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, name)
	}
}

type OAuthService struct {
	Providers map[string]goth.Provider
	config    *OAuthConfig
}

func NewOAuthService(config *OAuthConfig) *OAuthService {
	if config == nil {
		return nil
	}
	
	service := &OAuthService{
		Providers: make(map[string]goth.Provider),
		config:    config,
	}
	
	// Initialize providers from configuration
	for name, providerConfig := range config.Providers {
		provider, err := createGothProvider(name, providerConfig)
		if err != nil {
			continue
		}
		service.Providers[name] = provider
	}
	
	return service
}

func (o *OAuthService) RegisterProvider(name string, provider goth.Provider) {
	o.Providers[name] = provider
	goth.UseProviders(provider)
}

func (o *OAuthService) GetProvider(name string) (goth.Provider, error) {
	provider, exists := o.Providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

func (o *OAuthService) BeginAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		gothic.BeginAuthHandler(c.Writer, c.Request)
	}
}

// CompleteAuthHandler handles the OAuth callback
func (o *OAuthService) CompleteAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		providerName := c.Param("provider")
		if providerName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Provider not specified"})
			return
		}

		_, err := o.GetProvider(providerName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid provider"})
			return
		}

		gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed"})
			return
		}

		userInfo, err := o.MapGothUserToUserInfo(gothUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User mapping failed"})
			return
		}

		c.JSON(http.StatusOK, userInfo)
	}
}

// MapGothUserToUserInfo maps a Goth user to our UserInfo structure
func (o *OAuthService) MapGothUserToUserInfo(gothUser goth.User) (UserInfo, error) {
	if gothUser.Email == "" {
		return UserInfo{}, errors.New("email is required")
	}

	if o.config != nil && o.config.FindUserByEmail != nil {
		existingUser, err := o.config.FindUserByEmail(gothUser.Email)
		if err == nil {
			return existingUser, nil
		}
	}

	userInfo := UserInfo{
		Email: gothUser.Email,
		Role:  "user", // Default role for OAuth users
	}

	if gothUser.UserID != "" {
		if id, err := strconv.ParseUint(gothUser.UserID, 10, 32); err == nil {
			userInfo.ID = uint(id)
		}
	}

	return userInfo, nil
} 