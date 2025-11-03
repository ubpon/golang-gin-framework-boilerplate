// cmd/api/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"app/internal/auth"
	authHttp "app/internal/auth/delivery/http"
	authRepo "app/internal/auth/repository/postgres"
	authUsecase "app/internal/auth/usecase"
	"app/pkg/middleware"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize database
	db, err := initDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Run migrations
	if err := db.AutoMigrate(&auth.User{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize Gin
	router := gin.Default()

	// Apply global middleware
	router.Use(middleware.CORS())
	router.Use(middleware.RateLimiter())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestLogger())

	// Initialize modules
	initAuthModule(router, db)

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Start server with graceful shutdown
	srv := &http.Server{
		Addr:         ":" + getEnv("PORT", "8080"),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Server starting on port %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

func initDB() (*gorm.DB, error) {
	dsn := getEnv("DATABASE_URL", "host=localhost user=postgres password=postgres dbname=myapp port=5432 sslmode=disable")
	
	// Try to connect
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		// If database doesn't exist, try to create it
		log.Println("Database doesn't exist, attempting to create it...")
		
		// Connect to postgres database to create our database
		createDBDSN := "host=localhost user=postgres password=postgres dbname=postgres port=5432 sslmode=disable"
		tempDB, err := gorm.Open(postgres.Open(createDBDSN), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		
		// Create database
		createSQL := "CREATE DATABASE myapp"
		if err := tempDB.Exec(createSQL).Error; err != nil {
			// Ignore error if database already exists
			if !strings.Contains(err.Error(), "already exists") {
				return nil, err
			}
		}
		
		log.Println("Database created successfully")
		
		// Now connect to the new database
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, err
		}
	}
	
	return db, nil
}

func initAuthModule(router *gin.Engine, db *gorm.DB) {
	// Initialize layers
	userRepo := authRepo.NewUserRepository(db)
	authUC := authUsecase.NewAuthUsecase(userRepo, getEnv("JWT_SECRET", "your-secret-key"))
	
	// Register routes
	authHttp.NewAuthHandler(router, authUC)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}