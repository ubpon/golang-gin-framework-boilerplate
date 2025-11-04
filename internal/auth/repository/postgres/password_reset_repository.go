package postgres

import (
	"errors"
	"time"

	"app/internal/auth"

	"gorm.io/gorm"
)

type passwordResetRepository struct {
	db *gorm.DB
}

// NewPasswordResetRepository creates a new instance
func NewPasswordResetRepository(db *gorm.DB) auth.PasswordResetRepository {
	return &passwordResetRepository{db: db}
}

func (r *passwordResetRepository) Create(reset *auth.PasswordReset) error {
	return r.db.Create(reset).Error
}

func (r *passwordResetRepository) FindByToken(token string) (*auth.PasswordReset, error) {
	var reset auth.PasswordReset
	err := r.db.Where("token = ? AND used = ? AND expires_at > ?", 
		token, false, time.Now()).First(&reset).Error
	
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid or expired token")
		}
		return nil, err
	}
	return &reset, nil
}

func (r *passwordResetRepository) MarkAsUsed(id uint) error {
	return r.db.Model(&auth.PasswordReset{}).
		Where("id = ?", id).
		Update("used", true).Error
}

func (r *passwordResetRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ? OR used = ?", time.Now(), true).
		Delete(&auth.PasswordReset{}).Error
}