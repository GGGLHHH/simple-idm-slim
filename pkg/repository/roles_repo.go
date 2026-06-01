package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

// RolesRepository handles role persistence and user-role assignments.
type RolesRepository struct {
	db *sql.DB
}

// NewRolesRepository creates a new roles repository.
func NewRolesRepository(db *sql.DB) *RolesRepository {
	return &RolesRepository{db: db}
}

// Create creates a role with the given name.
func (r *RolesRepository) Create(ctx context.Context, name string) (*domain.Role, error) {
	if name == "" {
		return nil, domain.ErrInvalidRoleName
	}

	query := `
		INSERT INTO roles (name)
		VALUES ($1)
		RETURNING id, name, created_at, updated_at
	`
	return scanRole(r.db.QueryRowContext(ctx, query, name))
}

// Ensure returns an existing role by name or creates it.
func (r *RolesRepository) Ensure(ctx context.Context, name string) (*domain.Role, error) {
	if name == "" {
		return nil, domain.ErrInvalidRoleName
	}

	query := `
		INSERT INTO roles (name)
		VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		RETURNING id, name, created_at, updated_at
	`
	return scanRole(r.db.QueryRowContext(ctx, query, name))
}

// GetByID retrieves a role by ID.
func (r *RolesRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	query := `
		SELECT id, name, created_at, updated_at
		FROM roles
		WHERE id = $1
	`
	role, err := scanRole(r.db.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRoleNotFound
	}
	return role, err
}

// GetByName retrieves a role by name.
func (r *RolesRepository) GetByName(ctx context.Context, name string) (*domain.Role, error) {
	if name == "" {
		return nil, domain.ErrInvalidRoleName
	}

	query := `
		SELECT id, name, created_at, updated_at
		FROM roles
		WHERE name = $1
	`
	role, err := scanRole(r.db.QueryRowContext(ctx, query, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrRoleNotFound
	}
	return role, err
}

// List returns all roles ordered by name.
func (r *RolesRepository) List(ctx context.Context) ([]*domain.Role, error) {
	query := `
		SELECT id, name, created_at, updated_at
		FROM roles
		ORDER BY name ASC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []*domain.Role{}
	for rows.Next() {
		role := &domain.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

// Delete deletes a role and cascades user-role assignments.
func (r *RolesRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

// AssignToUser assigns a role to a user. Duplicate assignments are ignored.
func (r *RolesRepository) AssignToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	return err
}

// RemoveFromUser removes a role assignment from a user.
func (r *RolesRepository) RemoveFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	return err
}

// SetUserRoles replaces all role assignments for a user.
func (r *RolesRepository) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return Tx(ctx, r.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID); err != nil {
			return err
		}
		for _, roleID := range roleIDs {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO user_roles (user_id, role_id)
				VALUES ($1, $2)
				ON CONFLICT (user_id, role_id) DO NOTHING
			`, userID, roleID); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetUserRoles returns roles assigned to a user ordered by role name.
func (r *RolesRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*domain.Role, error) {
	query := `
		SELECT r.id, r.name, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		ORDER BY r.name ASC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []*domain.Role{}
	for rows.Next() {
		role := &domain.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

// GetUserRoleNames returns role names assigned to a user ordered by role name.
func (r *RolesRepository) GetUserRoleNames(ctx context.Context, userID uuid.UUID) ([]string, error) {
	roles, err := r.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names, nil
}

func scanRole(row *sql.Row) (*domain.Role, error) {
	role := &domain.Role{}
	if err := row.Scan(&role.ID, &role.Name, &role.CreatedAt, &role.UpdatedAt); err != nil {
		return nil, err
	}
	return role, nil
}
