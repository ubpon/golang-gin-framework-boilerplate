package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		
		log.Printf("[%s] %s %s - Status: %d - Duration: %v",
			method,
			path,
			c.ClientIP(),
			statusCode,
			latency,
		)
	}
}