package auth

import (
	"time"

	"gorm.io/gorm"
)

type PasswordReset struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	UserID    uint           `gorm:"not null;index" json:"user_id"`
	Token     string         `gorm:"uniqueIndex;not null" json:"token"`
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	Used      bool           `gorm:"default:false" json:"used"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type PasswordResetRepository interface {
	Create(reset *PasswordReset) error
	FindByToken(token string) (*PasswordReset, error)
	MarkAsUsed(id uint) error
	DeleteExpired() error
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

type AuthUsecaseExtended interface {
	AuthUsecase
	ForgotPassword(req ForgotPasswordRequest) (*ForgotPasswordResponse, error)
	ResetPassword(req ResetPasswordRequest) error
}