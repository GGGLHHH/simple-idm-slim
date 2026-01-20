package idm

import (
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate runs all pending database migrations.
// Call this before creating an IDM instance:
//
//	db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")
//	if err := idm.Migrate(db); err != nil {
//	    log.Fatal(err)
//	}
//	auth, _ := idm.New(idm.Config{DB: db, JWTSecret: "..."})
func Migrate(db *sql.DB) error {
	goose.SetBaseFS(migrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.Up(db, "migrations")
}

// MigrateDown rolls back the last migration.
func MigrateDown(db *sql.DB) error {
	goose.SetBaseFS(migrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.Down(db, "migrations")
}

// MigrateReset rolls back all migrations and re-applies them.
func MigrateReset(db *sql.DB) error {
	goose.SetBaseFS(migrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	if err := goose.Reset(db, "migrations"); err != nil {
		return err
	}

	return goose.Up(db, "migrations")
}

// MigrateStatus prints the migration status to stdout.
func MigrateStatus(db *sql.DB) error {
	goose.SetBaseFS(migrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	return goose.Status(db, "migrations")
}
