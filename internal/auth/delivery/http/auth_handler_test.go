// internal/auth/delivery/http/auth_handler_test.go
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"app/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock AuthUsecase
type MockAuthUsecase struct {
	mock.Mock
}

func (m *MockAuthUsecase) Register(req auth.RegisterRequest) (*auth.AuthResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *MockAuthUsecase) Login(req auth.LoginRequest) (*auth.AuthResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *MockAuthUsecase) Logout(userID uint) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockAuthUsecase) GetProfile(userID uint) (*auth.UserResponse, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.UserResponse), args.Error(1)
}

func (m *MockAuthUsecase) ChangePassword(userID uint, req auth.ChangePasswordRequest) error {
	args := m.Called(userID, req)
	return args.Error(0)
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestRegister_Success(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/register", handler.Register)

	registerReq := auth.RegisterRequest{
		Email:     "test@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	expectedResponse := &auth.AuthResponse{
		Token: "mock-jwt-token",
		User: &auth.UserResponse{
			ID:        1,
			Email:     "test@example.com",
			FirstName: "John",
			LastName:  "Doe",
			IsActive:  true,
			CreatedAt: time.Now(),
		},
	}

	mockUsecase.On("Register", registerReq).Return(expectedResponse, nil)

	body, _ := json.Marshal(registerReq)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "User registered successfully", response["message"])
	assert.NotNil(t, response["data"])
	
	mockUsecase.AssertExpectations(t)
}

func TestRegister_InvalidInput(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/register", handler.Register)

	// Missing required fields
	invalidReq := map[string]string{
		"email": "invalid-email",
	}

	body, _ := json.Marshal(invalidReq)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/register", handler.Register)

	registerReq := auth.RegisterRequest{
		Email:     "existing@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	mockUsecase.On("Register", registerReq).Return(nil, errors.New("email already registered"))

	body, _ := json.Marshal(registerReq)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "email already registered", response["error"])
	
	mockUsecase.AssertExpectations(t)
}

func TestLogin_Success(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/login", handler.Login)

	loginReq := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	expectedResponse := &auth.AuthResponse{
		Token: "mock-jwt-token",
		User: &auth.UserResponse{
			ID:        1,
			Email:     "test@example.com",
			FirstName: "John",
			LastName:  "Doe",
			IsActive:  true,
			CreatedAt: time.Now(),
		},
	}

	mockUsecase.On("Login", loginReq).Return(expectedResponse, nil)

	body, _ := json.Marshal(loginReq)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Login successful", response["message"])
	assert.NotNil(t, response["data"])
	
	mockUsecase.AssertExpectations(t)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/login", handler.Login)

	loginReq := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	mockUsecase.On("Login", loginReq).Return(nil, errors.New("invalid credentials"))

	body, _ := json.Marshal(loginReq)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "invalid credentials", response["error"])
	
	mockUsecase.AssertExpectations(t)
}

func TestLogin_InvalidInput(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.POST("/login", handler.Login)

	invalidReq := map[string]string{
		"email": "not-an-email",
	}

	body, _ := json.Marshal(invalidReq)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogout_Success(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	// Middleware to set user_id
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Next()
	})
	router.POST("/logout", handler.Logout)

	mockUsecase.On("Logout", uint(1)).Return(nil)

	req, _ := http.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Logout successful", response["message"])
	
	mockUsecase.AssertExpectations(t)
}

func TestGetProfile_Success(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Next()
	})
	router.GET("/profile", handler.GetProfile)

	expectedProfile := &auth.UserResponse{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	mockUsecase.On("GetProfile", uint(1)).Return(expectedProfile, nil)

	req, _ := http.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Profile retrieved successfully", response["message"])
	assert.NotNil(t, response["data"])
	
	mockUsecase.AssertExpectations(t)
}

func TestGetProfile_UserNotFound(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(999))
		c.Next()
	})
	router.GET("/profile", handler.GetProfile)

	mockUsecase.On("GetProfile", uint(999)).Return(nil, errors.New("user not found"))

	req, _ := http.NewRequest("GET", "/profile", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "user not found", response["error"])
	
	mockUsecase.AssertExpectations(t)
}

func TestChangePassword_Success(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Next()
	})
	router.PUT("/change-password", handler.ChangePassword)

	changePassReq := auth.ChangePasswordRequest{
		CurrentPassword: "oldpassword123",
		NewPassword:     "newpassword123",
	}

	mockUsecase.On("ChangePassword", uint(1), changePassReq).Return(nil)

	body, _ := json.Marshal(changePassReq)
	req, _ := http.NewRequest("PUT", "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Password changed successfully", response["message"])
	
	mockUsecase.AssertExpectations(t)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Next()
	})
	router.PUT("/change-password", handler.ChangePassword)

	changePassReq := auth.ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
	}

	mockUsecase.On("ChangePassword", uint(1), changePassReq).Return(errors.New("current password is incorrect"))

	body, _ := json.Marshal(changePassReq)
	req, _ := http.NewRequest("PUT", "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "current password is incorrect", response["error"])
	
	mockUsecase.AssertExpectations(t)
}

func TestChangePassword_InvalidInput(t *testing.T) {
	mockUsecase := new(MockAuthUsecase)
	router := setupTestRouter()
	handler := &authHandler{authUsecase: mockUsecase}

	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Next()
	})
	router.PUT("/change-password", handler.ChangePassword)

	invalidReq := map[string]string{
		"current_password": "old",
		"new_password":     "short", // Too short
	}

	body, _ := json.Marshal(invalidReq)
	req, _ := http.NewRequest("PUT", "/change-password", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}