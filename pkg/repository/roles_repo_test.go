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

func TestRolesRepository_EnsureListAndLookup(t *testing.T) {
	db := openRepositoryTestDB(t)
	ctx := context.Background()
	schema := setupRolesRepositorySchema(t, db)

	repo := NewRolesRepository(db)

	adminRole, err := repo.Ensure(ctx, "admin")
	if err != nil {
		t.Fatalf("ensure admin role: %v", err)
	}
	if adminRole.ID == uuid.Nil {
		t.Fatal("expected admin role ID to be set")
	}
	if adminRole.Name != "admin" {
		t.Fatalf("expected admin role name, got %q", adminRole.Name)
	}

	again, err := repo.Ensure(ctx, "admin")
	if err != nil {
		t.Fatalf("ensure existing admin role: %v", err)
	}
	if again.ID != adminRole.ID {
		t.Fatalf("expected ensure to return existing role ID %s, got %s", adminRole.ID, again.ID)
	}

	creatorRole, err := repo.Ensure(ctx, "creator")
	if err != nil {
		t.Fatalf("ensure creator role: %v", err)
	}

	roles, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	gotNames := roleNames(roles)
	wantNames := []string{"admin", "creator"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("role names mismatch: got %#v want %#v", gotNames, wantNames)
	}

	byName, err := repo.GetByName(ctx, "creator")
	if err != nil {
		t.Fatalf("get role by name: %v", err)
	}
	if byName.ID != creatorRole.ID {
		t.Fatalf("expected creator role ID %s, got %s", creatorRole.ID, byName.ID)
	}

	byID, err := repo.GetByID(ctx, adminRole.ID)
	if err != nil {
		t.Fatalf("get role by id: %v", err)
	}
	if byID.Name != "admin" {
		t.Fatalf("expected admin by id, got %q", byID.Name)
	}

	if _, err := repo.Ensure(ctx, ""); !errors.Is(err, domain.ErrInvalidRoleName) {
		t.Fatalf("expected ErrInvalidRoleName for empty role name, got %v", err)
	}

	execRepositoryTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
}

func TestRolesRepository_UserRoleAssignments(t *testing.T) {
	db := openRepositoryTestDB(t)
	ctx := context.Background()
	schema := setupRolesRepositorySchema(t, db)

	repo := NewRolesRepository(db)
	userID := insertRepositoryTestUser(t, db, "roles-user@example.com")
	adminRole, err := repo.Ensure(ctx, "admin")
	if err != nil {
		t.Fatalf("ensure admin role: %v", err)
	}
	creatorRole, err := repo.Ensure(ctx, "creator")
	if err != nil {
		t.Fatalf("ensure creator role: %v", err)
	}
	agentRole, err := repo.Ensure(ctx, "agent")
	if err != nil {
		t.Fatalf("ensure agent role: %v", err)
	}

	if err := repo.AssignToUser(ctx, userID, adminRole.ID); err != nil {
		t.Fatalf("assign admin role: %v", err)
	}
	if err := repo.AssignToUser(ctx, userID, adminRole.ID); err != nil {
		t.Fatalf("duplicate assign should be idempotent: %v", err)
	}

	names, err := repo.GetUserRoleNames(ctx, userID)
	if err != nil {
		t.Fatalf("get user role names: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"admin"}) {
		t.Fatalf("expected admin role names, got %#v", names)
	}

	if err := repo.SetUserRoles(ctx, userID, []uuid.UUID{creatorRole.ID, agentRole.ID}); err != nil {
		t.Fatalf("set user roles: %v", err)
	}
	names, err = repo.GetUserRoleNames(ctx, userID)
	if err != nil {
		t.Fatalf("get role names after set: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"agent", "creator"}) {
		t.Fatalf("expected replacement role names, got %#v", names)
	}

	roles, err := repo.GetUserRoles(ctx, userID)
	if err != nil {
		t.Fatalf("get user roles: %v", err)
	}
	if !reflect.DeepEqual(roleNames(roles), []string{"agent", "creator"}) {
		t.Fatalf("expected replacement roles, got %#v", roles)
	}

	if err := repo.RemoveFromUser(ctx, userID, agentRole.ID); err != nil {
		t.Fatalf("remove agent role: %v", err)
	}
	if err := repo.RemoveFromUser(ctx, userID, agentRole.ID); err != nil {
		t.Fatalf("removing missing role assignment should be idempotent: %v", err)
	}
	names, err = repo.GetUserRoleNames(ctx, userID)
	if err != nil {
		t.Fatalf("get role names after remove: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"creator"}) {
		t.Fatalf("expected creator role after remove, got %#v", names)
	}

	execRepositoryTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
}

func openRepositoryTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "postgres://xchangeai:pwd@localhost:5432/xchangeai?sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	if err := db.Ping(); err != nil {
		t.Skipf("skipping postgres integration test: %v", err)
	}
	return db
}

func setupRolesRepositorySchema(t *testing.T, db *sql.DB) string {
	t.Helper()

	schema := "roles_repo_test_" + uuid.NewString()
	execRepositoryTestSQL(t, db, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	t.Cleanup(func() {
		execRepositoryTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	})
	execRepositoryTestSQL(t, db, `SET search_path TO `+pq.QuoteIdentifier(schema)+`, public`)
	execRepositoryTestSQL(t, db, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			email TEXT NOT NULL UNIQUE
		)
	`)
	execRepositoryTestSQL(t, db, `
		CREATE TABLE roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL UNIQUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	execRepositoryTestSQL(t, db, `
		CREATE TABLE user_roles (
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (user_id, role_id)
		)
	`)
	return schema
}

func insertRepositoryTestUser(t *testing.T, db *sql.DB, email string) uuid.UUID {
	t.Helper()

	id := uuid.New()
	_, err := db.Exec(`INSERT INTO users (id, email) VALUES ($1, $2)`, id, email)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	return id
}

func execRepositoryTestSQL(t *testing.T, db *sql.DB, query string) {
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
