package usecase

import (
	"errors"
	"testing"
	"time"

	"app/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// Mock UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *auth.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(id uint) (*auth.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(email string) (*auth.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *auth.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func TestRegister_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	req := auth.RegisterRequest{
		Email:     "test@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	// Mock: Email doesn't exist
	mockRepo.On("FindByEmail", req.Email).Return(nil, errors.New("user not found"))
	
	// Mock: User creation succeeds
	mockRepo.On("Create", mock.AnythingOfType("*auth.User")).Return(nil).Run(func(args mock.Arguments) {
		user := args.Get(0).(*auth.User)
		user.ID = 1 // Simulate DB assigning ID
	})

	response, err := usecase.Register(req)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.Token)
	assert.Equal(t, req.Email, response.User.Email)
	assert.Equal(t, req.FirstName, response.User.FirstName)
	assert.Equal(t, req.LastName, response.User.LastName)
	assert.True(t, response.User.IsActive)
	
	mockRepo.AssertExpectations(t)
}

func TestRegister_EmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	req := auth.RegisterRequest{
		Email:     "existing@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	existingUser := &auth.User{
		ID:    1,
		Email: req.Email,
	}

	mockRepo.On("FindByEmail", req.Email).Return(existingUser, nil)

	response, err := usecase.Register(req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, "email already registered", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestRegister_CreateUserFails(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	req := auth.RegisterRequest{
		Email:     "test@example.com",
		Password:  "password123",
		FirstName: "John",
		LastName:  "Doe",
	}

	mockRepo.On("FindByEmail", req.Email).Return(nil, errors.New("user not found"))
	mockRepo.On("Create", mock.AnythingOfType("*auth.User")).Return(errors.New("database error"))

	response, err := usecase.Register(req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, "failed to create user", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestLogin_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:        1,
		Email:     "test@example.com",
		Password:  string(hashedPassword),
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	req := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("FindByEmail", req.Email).Return(user, nil)

	response, err := usecase.Login(req)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotEmpty(t, response.Token)
	assert.Equal(t, user.Email, response.User.Email)
	assert.Equal(t, user.ID, response.User.ID)
	
	mockRepo.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	req := auth.LoginRequest{
		Email:    "notfound@example.com",
		Password: "password123",
	}

	mockRepo.On("FindByEmail", req.Email).Return(nil, errors.New("user not found"))

	response, err := usecase.Login(req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, "invalid credentials", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestLogin_WrongPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}

	req := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	mockRepo.On("FindByEmail", req.Email).Return(user, nil)

	response, err := usecase.Login(req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, "invalid credentials", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestLogin_InactiveUser(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
		IsActive: false, // Inactive user
	}

	req := auth.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("FindByEmail", req.Email).Return(user, nil)

	response, err := usecase.Login(req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, "account is inactive", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	err := usecase.Logout(1)

	assert.NoError(t, err)
}

func TestGetProfile_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	user := &auth.User{
		ID:        1,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	mockRepo.On("FindByID", uint(1)).Return(user, nil)

	profile, err := usecase.GetProfile(1)

	assert.NoError(t, err)
	assert.NotNil(t, profile)
	assert.Equal(t, user.ID, profile.ID)
	assert.Equal(t, user.Email, profile.Email)
	assert.Equal(t, user.FirstName, profile.FirstName)
	
	mockRepo.AssertExpectations(t)
}

func TestGetProfile_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	mockRepo.On("FindByID", uint(999)).Return(nil, errors.New("user not found"))

	profile, err := usecase.GetProfile(999)

	assert.Error(t, err)
	assert.Nil(t, profile)
	assert.Equal(t, "user not found", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestChangePassword_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	oldHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(oldHashedPassword),
	}

	req := auth.ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword123",
	}

	mockRepo.On("FindByID", uint(1)).Return(user, nil)
	mockRepo.On("Update", mock.AnythingOfType("*auth.User")).Return(nil)

	err := usecase.ChangePassword(1, req)

	assert.NoError(t, err)
	
	// Verify new password was hashed
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.NewPassword))
	assert.NoError(t, err)
	
	mockRepo.AssertExpectations(t)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	req := auth.ChangePasswordRequest{
		CurrentPassword: "wrongpassword",
		NewPassword:     "newpassword123",
	}

	mockRepo.On("FindByID", uint(1)).Return(user, nil)

	err := usecase.ChangePassword(1, req)

	assert.Error(t, err)
	assert.Equal(t, "current password is incorrect", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestChangePassword_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	req := auth.ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword123",
	}

	mockRepo.On("FindByID", uint(999)).Return(nil, errors.New("user not found"))

	err := usecase.ChangePassword(999, req)

	assert.Error(t, err)
	assert.Equal(t, "user not found", err.Error())
	
	mockRepo.AssertExpectations(t)
}

func TestChangePassword_UpdateFails(t *testing.T) {
	mockRepo := new(MockUserRepository)
	usecase := NewAuthUsecase(mockRepo, "test-secret")

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	
	user := &auth.User{
		ID:       1,
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	req := auth.ChangePasswordRequest{
		CurrentPassword: "oldpassword",
		NewPassword:     "newpassword123",
	}

	mockRepo.On("FindByID", uint(1)).Return(user, nil)
	mockRepo.On("Update", mock.AnythingOfType("*auth.User")).Return(errors.New("database error"))

	err := usecase.ChangePassword(1, req)

	assert.Error(t, err)
	assert.Equal(t, "failed to update password", err.Error())
	
	mockRepo.AssertExpectations(t)
}