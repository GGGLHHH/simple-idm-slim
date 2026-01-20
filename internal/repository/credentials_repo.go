package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/domain"
)

// CredentialsRepository handles password credentials persistence.
type CredentialsRepository struct {
	db *sql.DB
}

// NewCredentialsRepository creates a new credentials repository.
func NewCredentialsRepository(db *sql.DB) *CredentialsRepository {
	return &CredentialsRepository{db: db}
}

// Create creates a new password credential.
func (r *CredentialsRepository) Create(ctx context.Context, cred *domain.UserPassword) error {
	query := `
		INSERT INTO user_password (user_id, password_hash, password_updated_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query,
		cred.UserID, cred.PasswordHash, cred.PasswordUpdatedAt,
	)
	return err
}

// CreateTx creates a new password credential within a transaction.
func (r *CredentialsRepository) CreateTx(ctx context.Context, tx *sql.Tx, cred *domain.UserPassword) error {
	query := `
		INSERT INTO user_password (user_id, password_hash, password_updated_at)
		VALUES ($1, $2, $3)
	`
	_, err := tx.ExecContext(ctx, query,
		cred.UserID, cred.PasswordHash, cred.PasswordUpdatedAt,
	)
	return err
}

// GetByUserID retrieves password credential by user ID.
func (r *CredentialsRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.UserPassword, error) {
	query := `
		SELECT user_id, password_hash, password_updated_at
		FROM user_password
		WHERE user_id = $1
	`
	cred := &domain.UserPassword{}
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&cred.UserID, &cred.PasswordHash, &cred.PasswordUpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// Update updates the password hash.
func (r *CredentialsRepository) Update(ctx context.Context, cred *domain.UserPassword) error {
	query := `
		UPDATE user_password
		SET password_hash = $2, password_updated_at = NOW()
		WHERE user_id = $1
	`
	result, err := r.db.ExecContext(ctx, query, cred.UserID, cred.PasswordHash)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

// Delete deletes a password credential.
func (r *CredentialsRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM user_password WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// Exists checks if a user has a password credential.
func (r *CredentialsRepository) Exists(ctx context.Context, userID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM user_password WHERE user_id = $1)`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&exists)
	return exists, err
}
