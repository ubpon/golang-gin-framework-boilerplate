package http

import (
	"net/http"

	"app/internal/auth"
	"app/pkg/middleware"

	"github.com/gin-gonic/gin"
)

type authHandler struct {
	authUsecase auth.AuthUsecase
}

func NewAuthHandler(router *gin.Engine, authUC auth.AuthUsecase) {
	handler := &authHandler{
		authUsecase: authUC,
	}

	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/register", handler.Register)
		authGroup.POST("/login", handler.Login)
	}

	protectedGroup := router.Group("/api/v1/auth")
	protectedGroup.Use(middleware.AuthMiddleware())
	{
		protectedGroup.POST("/logout", handler.Logout)
		protectedGroup.GET("/profile", handler.GetProfile)
		protectedGroup.PUT("/change-password", handler.ChangePassword)
	}
}

func (h *authHandler) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authUsecase.Register(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"data":    response,
	})
}

func (h *authHandler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authUsecase.Login(req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data":    response,
	})
}

func (h *authHandler) Logout(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	if err := h.authUsecase.Logout(userID.(uint)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

func (h *authHandler) GetProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	profile, err := h.authUsecase.GetProfile(userID.(uint))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile retrieved successfully",
		"data":    profile,
	})
}

func (h *authHandler) ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req auth.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authUsecase.ChangePassword(userID.(uint), req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}