package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// IdentitiesRepository handles external identity persistence.
type IdentitiesRepository struct {
	db *sql.DB
}

// NewIdentitiesRepository creates a new identities repository.
func NewIdentitiesRepository(db *sql.DB) *IdentitiesRepository {
	return &IdentitiesRepository{db: db}
}

// Create creates a new external identity.
func (r *IdentitiesRepository) Create(ctx context.Context, identity *domain.UserIdentity) error {
	query := `
		INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(ctx, query,
		identity.ID, identity.UserID, identity.Provider,
		identity.ProviderSubject, identity.Email, identity.CreatedAt,
	)
	return err
}

// CreateTx creates a new external identity within a transaction.
func (r *IdentitiesRepository) CreateTx(ctx context.Context, tx *sql.Tx, identity *domain.UserIdentity) error {
	query := `
		INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		identity.ID, identity.UserID, identity.Provider,
		identity.ProviderSubject, identity.Email, identity.CreatedAt,
	)
	return err
}

// GetByProviderSubject retrieves an identity by provider and subject.
func (r *IdentitiesRepository) GetByProviderSubject(ctx context.Context, provider, subject string) (*domain.UserIdentity, error) {
	query := `
		SELECT id, user_id, provider, provider_subject, email, created_at
		FROM user_identities
		WHERE provider = $1 AND provider_subject = $2
	`
	identity := &domain.UserIdentity{}
	err := r.db.QueryRowContext(ctx, query, provider, subject).Scan(
		&identity.ID, &identity.UserID, &identity.Provider,
		&identity.ProviderSubject, &identity.Email, &identity.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// GetByUserID retrieves all identities for a user.
func (r *IdentitiesRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.UserIdentity, error) {
	query := `
		SELECT id, user_id, provider, provider_subject, email, created_at
		FROM user_identities
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []*domain.UserIdentity
	for rows.Next() {
		identity := &domain.UserIdentity{}
		err := rows.Scan(
			&identity.ID, &identity.UserID, &identity.Provider,
			&identity.ProviderSubject, &identity.Email, &identity.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

// Delete deletes an identity.
func (r *IdentitiesRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_identities WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// DeleteByUserID deletes all identities for a user.
func (r *IdentitiesRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM user_identities WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}
