package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_AllowsNormalTraffic(t *testing.T) {
	// Reset visitors map
	visitors = make(map[string]*visitor)

	router := setupTestRouter()
	router.Use(RateLimiter())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Make 10 requests (well below limit)
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestRateLimiter_BlocksExcessiveTraffic(t *testing.T) {
	// Reset visitors map
	visitors = make(map[string]*visitor)

	router := setupTestRouter()
	router.Use(RateLimiter())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Make 101 requests (over limit of 100)
	var lastStatus int
	for i := 0; i < 101; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		lastStatus = w.Code
	}

	// Last request should be rate limited
	assert.Equal(t, http.StatusTooManyRequests, lastStatus)
}