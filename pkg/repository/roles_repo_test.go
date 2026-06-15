package repository

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/tendant/simple-idm-slim/pkg/domain"
)

func TestRolesRepository_CRUDAndUpdate(t *testing.T) {
	db := openRolesTestDB(t)
	ctx := context.Background()
	setupRolesTestSchema(t, db)
	repo := NewRolesRepository(db)

	// Create
	admin, err := repo.Create(ctx, "admin")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if admin.ID == uuid.Nil || admin.Name != "admin" {
		t.Fatalf("unexpected admin role: %#v", admin)
	}

	// Create duplicate -> ErrRoleAlreadyExists
	if _, err := repo.Create(ctx, "admin"); !errors.Is(err, domain.ErrRoleAlreadyExists) {
		t.Fatalf("expected ErrRoleAlreadyExists, got %v", err)
	}

	// Create empty -> ErrInvalidRoleName
	if _, err := repo.Create(ctx, ""); !errors.Is(err, domain.ErrInvalidRoleName) {
		t.Fatalf("expected ErrInvalidRoleName, got %v", err)
	}

	// GetByName / GetByID
	byName, err := repo.GetByName(ctx, "admin")
	if err != nil || byName.ID != admin.ID {
		t.Fatalf("get by name: %v role=%#v", err, byName)
	}
	if _, err := repo.GetByName(ctx, "nope"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("expected ErrRoleNotFound, got %v", err)
	}

	// List ordered by name
	if _, err := repo.Create(ctx, "creator"); err != nil {
		t.Fatalf("create creator: %v", err)
	}
	roles, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := roleNames(roles); !reflect.DeepEqual(got, []string{"admin", "creator"}) {
		t.Fatalf("list mismatch: %#v", got)
	}

	// Update (rename) success
	renamed, err := repo.Update(ctx, admin.ID, "platform_admin")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if renamed.Name != "platform_admin" {
		t.Fatalf("expected renamed name, got %q", renamed.Name)
	}

	// Update to an existing name -> ErrRoleAlreadyExists
	if _, err := repo.Update(ctx, admin.ID, "creator"); !errors.Is(err, domain.ErrRoleAlreadyExists) {
		t.Fatalf("expected ErrRoleAlreadyExists on rename, got %v", err)
	}

	// Update non-existent ID -> ErrRoleNotFound
	if _, err := repo.Update(ctx, uuid.New(), "ghost"); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("expected ErrRoleNotFound on rename, got %v", err)
	}

	// Update empty name -> ErrInvalidRoleName
	if _, err := repo.Update(ctx, admin.ID, ""); !errors.Is(err, domain.ErrInvalidRoleName) {
		t.Fatalf("expected ErrInvalidRoleName on rename, got %v", err)
	}

	// Delete
	if err := repo.Delete(ctx, admin.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, admin.ID); !errors.Is(err, domain.ErrRoleNotFound) {
		t.Fatalf("expected ErrRoleNotFound after delete, got %v", err)
	}
}

func TestRolesRepository_UserAssignment(t *testing.T) {
	db := openRolesTestDB(t)
	ctx := context.Background()
	setupRolesTestSchema(t, db)
	repo := NewRolesRepository(db)

	userID := insertRolesTestUser(t, db, "user@example.com")
	admin, _ := repo.Ensure(ctx, "admin")
	creator, _ := repo.Ensure(ctx, "creator")

	// Ensure is idempotent
	again, err := repo.Ensure(ctx, "admin")
	if err != nil || again.ID != admin.ID {
		t.Fatalf("ensure idempotency: %v id=%v", err, again)
	}

	// Assign (idempotent)
	if err := repo.AssignToUser(ctx, userID, admin.ID); err != nil {
		t.Fatalf("assign admin: %v", err)
	}
	if err := repo.AssignToUser(ctx, userID, admin.ID); err != nil {
		t.Fatalf("assign admin again: %v", err)
	}
	names, err := repo.GetUserRoleNames(ctx, userID)
	if err != nil || !reflect.DeepEqual(names, []string{"admin"}) {
		t.Fatalf("user role names: %v %#v", err, names)
	}

	// SetUserRoles replaces
	if err := repo.SetUserRoles(ctx, userID, []uuid.UUID{creator.ID}); err != nil {
		t.Fatalf("set user roles: %v", err)
	}
	names, _ = repo.GetUserRoleNames(ctx, userID)
	if !reflect.DeepEqual(names, []string{"creator"}) {
		t.Fatalf("after set: %#v", names)
	}

	// RemoveFromUser
	if err := repo.RemoveFromUser(ctx, userID, creator.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	names, _ = repo.GetUserRoleNames(ctx, userID)
	if len(names) != 0 {
		t.Fatalf("expected no roles, got %#v", names)
	}
}

// --- test harness helpers ---

func openRolesTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "postgres://xchangeai:pwd@localhost:5432/xchangeai?sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("skipping postgres integration test: %v", err)
	}
	return db
}

func setupRolesTestSchema(t *testing.T, db *sql.DB) string {
	t.Helper()
	schema := "roles_repo_test_" + uuid.NewString()
	execRolesTestSQL(t, db, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	t.Cleanup(func() {
		execRolesTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	})
	execRolesTestSQL(t, db, `SET search_path TO `+pq.QuoteIdentifier(schema)+`, public`)
	execRolesTestSQL(t, db, `CREATE TABLE users (id UUID PRIMARY KEY, email TEXT NOT NULL UNIQUE)`)
	execRolesTestSQL(t, db, `
		CREATE TABLE roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL UNIQUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	execRolesTestSQL(t, db, `
		CREATE TABLE user_roles (
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (user_id, role_id)
		)`)
	return schema
}

func insertRolesTestUser(t *testing.T, db *sql.DB, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, email) VALUES ($1, $2)`, id, email); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	return id
}

func execRolesTestSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func roleNames(roles []*domain.Role) []string {
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names
}
