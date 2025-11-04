package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func generateTestToken(userID uint, secret string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestAuthMiddleware_Success(t *testing.T) {
	router := setupTestRouter()
	secret := "test-secret"
	os.Setenv("JWT_SECRET", secret)
	defer os.Unsetenv("JWT_SECRET")

	var capturedUserID uint
	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		capturedUserID = userID.(uint)
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	token := generateTestToken(123, secret)

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, uint(123), capturedUserID)
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	router := setupTestRouter()
	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	router := setupTestRouter()
	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "InvalidFormat token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid authorization header format")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	router := setupTestRouter()
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_SECRET")

	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	router := setupTestRouter()
	secret := "test-secret"
	os.Setenv("JWT_SECRET", secret)
	defer os.Unsetenv("JWT_SECRET")

	router.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create expired token
	claims := jwt.MapClaims{
		"user_id": 123,
		"exp":     time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat":     time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}