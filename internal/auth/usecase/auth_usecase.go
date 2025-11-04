// internal/auth/usecase/auth_usecase.go
package usecase

import (
	"errors"
	"time"

	"app/internal/auth"

	"app/pkg/email"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	userRepo  auth.UserRepository
	passwordResetRepo auth.PasswordResetRepository
	emailService      *email.EmailService
	jwtSecret string
}

// NewAuthUsecase creates a new instance of authUsecase
func NewAuthUsecase(
	userRepo auth.UserRepository,
	passwordResetRepo auth.PasswordResetRepository,
	emailService *email.EmailService,
	jwtSecret string,
) auth.AuthUsecase {
	return &authUsecase{
		userRepo:  userRepo,
		passwordResetRepo: passwordResetRepo,
		emailService:      emailService,
		jwtSecret: jwtSecret,
	}
}

func (u *authUsecase) Register(req auth.RegisterRequest) (*auth.AuthResponse, error) {
	// Check if user already exists
	existingUser, _ := u.userRepo.FindByEmail(req.Email)
	if existingUser != nil {
		return nil, errors.New("email already registered")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	// Create user
	user := &auth.User{
		Email:     req.Email,
		Password:  string(hashedPassword),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IsActive:  true,
	}

	if err := u.userRepo.Create(user); err != nil {
		return nil, errors.New("failed to create user")
	}

	// Generate JWT token
	token, err := u.generateToken(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate token")
	}

	return &auth.AuthResponse{
		Token: token,
		User:  user.ToUserResponse(),
	}, nil
}

func (u *authUsecase) Login(req auth.LoginRequest) (*auth.AuthResponse, error) {
	// Find user by email
	user, err := u.userRepo.FindByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Generate JWT token
	token, err := u.generateToken(user.ID)
	if err != nil {
		return nil, errors.New("failed to generate token")
	}

	return &auth.AuthResponse{
		Token: token,
		User:  user.ToUserResponse(),
	}, nil
}

func (u *authUsecase) Logout(userID uint) error {
	// In a production environment, you might want to:
	// 1. Blacklist the token
	// 2. Clear refresh tokens from database
	// 3. Log the logout event
	return nil
}

func (u *authUsecase) GetProfile(userID uint) (*auth.UserResponse, error) {
	user, err := u.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return user.ToUserResponse(), nil
}

func (u *authUsecase) ChangePassword(userID uint, req auth.ChangePasswordRequest) error {
	// Find user
	user, err := u.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// Update password
	user.Password = string(hashedPassword)
	if err := u.userRepo.Update(user); err != nil {
		return errors.New("failed to update password")
	}

	go u.emailService.SendPasswordResetConfirmation(user.Email, user.FirstName)

	return nil
}

func (u *authUsecase) ForgotPassword(req auth.ForgotPasswordRequest) (*auth.ForgotPasswordResponse, error) {
	user, err := u.userRepo.FindByEmail(req.Email)
	if err != nil {
		return &auth.ForgotPasswordResponse{
			Message: "If an account exists with this email, you will receive a password reset link",
		}, nil
	}

	resetToken := email.GenerateResetToken()
	
	passwordReset := &auth.PasswordReset{
		UserID:    user.ID,
		Token:     resetToken,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiration
		Used:      false,
	}

	if err := u.passwordResetRepo.Create(passwordReset); err != nil {
		return nil, errors.New("failed to create password reset token")
	}

	go u.emailService.SendForgotPasswordEmail(user.Email, user.FirstName, resetToken)

	return &auth.ForgotPasswordResponse{
		Message: "If an account exists with this email, you will receive a password reset link",
	}, nil
}

func (u *authUsecase) generateToken(userID uint) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 hours
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(u.jwtSecret))
}