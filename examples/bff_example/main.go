package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	auth "github.com/ExpanseVR/gin-auth-kit"
	"github.com/ExpanseVR/gin-auth-kit/utils"
	"github.com/gin-gonic/gin"
)

// Simple in-memory session store (use Redis/Database in production)
type SimpleSessionStore struct {
	sessions map[string]auth.UserInfo
	mutex    sync.RWMutex
}

func (s *SimpleSessionStore) CreateSession(user auth.UserInfo, expiry time.Duration) (string, error) {
	sid, err := utils.GenerateSecureSID()
	if err != nil {
		return "", err
	}

	s.mutex.Lock()
	s.sessions[sid] = user
	s.mutex.Unlock()

	return sid, nil
}

func (s *SimpleSessionStore) ValidateSession(sid string) (auth.UserInfo, error) {
	s.mutex.RLock()
	user, exists := s.sessions[sid]
	s.mutex.RUnlock()

	if !exists {
		return auth.UserInfo{}, errors.New("session not found")
	}
	return user, nil
}

func (s *SimpleSessionStore) GetSession(sid string) (auth.UserInfo, error) {
	return s.ValidateSession(sid)
}

func (s *SimpleSessionStore) DeleteSession(sid string) error {
	s.mutex.Lock()
	delete(s.sessions, sid)
	s.mutex.Unlock()
	return nil
}

// Mock database functions
func findUserByEmail(email string) (auth.UserInfo, error) {
	if email == "user@example.com" {
		return auth.UserInfo{
			ID:           1,
			Email:        email,
			Role:         "user",
			PasswordHash: "$2a$12$YYFDEkZTj3cdSwwEV8bKKe5QPCYX8gGTY.faRdFApR7BOX0DvXiau", // "password123"
		}, nil
	}
	return auth.UserInfo{}, errors.New("user not found")
}

func findUserByID(id uint) (auth.UserInfo, error) {
	if id == 1 {
		return auth.UserInfo{
			ID:           1,
			Email:        "user@example.com",
			Role:         "user",
			PasswordHash: "$2a$12$YYFDEkZTj3cdSwwEV8bKKe5QPCYX8gGTY.faRdFApR7BOX0DvXiau", // "password123"
		}, nil
	}
	return auth.UserInfo{}, errors.New("user not found")
}

func loginHandler(bffService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginReq struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		user, err := findUserByEmail(loginReq.Email)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		if err := utils.VerifyPassword(user.PasswordHash, loginReq.Password); err != nil {
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		sessionStore := bffService.BFF.Sessions
		sid, err := sessionStore.CreateSession(user, 24*time.Hour)
		if err != nil {
			c.JSON(500, gin.H{"error": "Session creation failed"})
			return
		}

		auth.SetSIDCookie(c, sid, auth.CookieConfig{
			Name:     "sid",
			Path:     "/",
			MaxAge:   86400,
			HttpOnly: true,
			Secure:   false, // Set true in production with HTTPS
			SameSite: http.SameSiteLaxMode,
		})

		c.JSON(200, gin.H{
			"message": "Login successful",
			"user": gin.H{
				"id":    user.ID,
				"email": user.Email,
				"role":  user.Role,
			},
		})
	}
}

func logoutHandler(bffService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := auth.GetSIDCookie(c, "sid")
		if sid != "" {
			sessionStore := bffService.BFF.Sessions
			sessionStore.DeleteSession(sid)
		}

		auth.ClearSIDCookie(c, "sid")

		c.JSON(200, gin.H{"message": "Logout successful"})
	}
}

// JWT exchange handler (for microservice calls)
func exchangeHandler(bffService *auth.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		sid := auth.GetSIDCookie(c, "sid")
		if sid == "" {
			c.JSON(401, gin.H{"error": "No session"})
			return
		}

		jwt, err := bffService.BFF.Exchange.ExchangeSessionForJWT(sid)
		if err != nil {
			c.JSON(500, gin.H{"error": "Token generation failed"})
			return
		}

		c.JSON(200, gin.H{
			"jwt": jwt,
			"message": "JWT token generated for microservice communication",
		})
	}
}

func profileHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(500, gin.H{"error": "User not found"})
		return
	}
	userInfo := user.(auth.UserInfo)

	c.JSON(200, gin.H{
		"user_id": userInfo.ID,
		"email":   userInfo.Email,
		"role":    userInfo.Role,
		"message": "Accessed via secure session!",
	})
}

func adminHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(500, gin.H{"error": "User not found"})
		return
	}
	userInfo := user.(auth.UserInfo)

	if userInfo.Role != "admin" {
		c.JSON(403, gin.H{"error": "Admin access required"})
		return
	}

	c.JSON(200, gin.H{
		"message": "Admin access granted",
		"user":    userInfo,
	})
}

func publicHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(200, gin.H{
			"message": "Public endpoint - no session required",
		})
		return
	}

	userInfo := user.(auth.UserInfo)
	c.JSON(200, gin.H{
		"message": "Public endpoint - session found",
		"user": gin.H{
			"id":    userInfo.ID,
			"email": userInfo.Email,
		},
	})
}

func main() {
	// Simple session store
	sessionStore := &SimpleSessionStore{
		sessions: make(map[string]auth.UserInfo),
	}

	// BFF configuration
	opts := &auth.BFFAuthOptions{
		JWTSecret:     "your-jwt-secret-change-in-production",
		JWTExpiry:     10 * time.Minute,
		SessionSecret: "your-session-secret-change-in-production",
		SessionMaxAge: 86400, // 24 hours
		SIDCookieName: "sid",
		SessionService: sessionStore,

		FindUserByEmail: findUserByEmail,
		FindUserByID:    findUserByID,
	}

	bffService, err := auth.NewBFFAuthService(opts)
	if err != nil {
		log.Fatal("BFF setup failed:", err)
	}

	router := gin.Default()
	router.Use(gin.Logger())

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "BFF Authentication Example",
			"endpoints": gin.H{
				"login":    "POST /login",
				"logout":   "POST /logout",
				"exchange": "POST /exchange",
				"profile":  "GET /profile",
				"admin":    "GET /admin",
				"public":   "GET /public",
			},
		})
	})

	authGroup := router.Group("/api/auth")
	{
		authGroup.POST("/login", loginHandler(bffService))
		authGroup.POST("/logout", logoutHandler(bffService))
		authGroup.POST("/exchange", exchangeHandler(bffService))
	}

	protected := router.Group("/api/protected")
	protected.Use(bffService.BFF.Middleware.RequireSession())
	{
		protected.GET("/profile", profileHandler)
		protected.GET("/admin", adminHandler)
	}

	router.GET("/api/public", bffService.BFF.Middleware.OptionalSession(), publicHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("BFF Authentication Example Server running on :%s", port)
	router.Run(":" + port)
} 