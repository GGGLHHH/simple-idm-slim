# simple-idm-slim

A minimal, embeddable identity management library for Go applications.

## Features

- Email + password authentication with Argon2id hashing
- Google OAuth authentication
- JWT access tokens + opaque refresh tokens
- Session management with token revocation
- User profile management
- Built on chi router with standard library compatibility

## Installation

```bash
go get github.com/tendant/simple-idm-slim
```

## Quick Start

### 1. Run migrations

Copy migrations to your project and run with your preferred tool:

```bash
# Using goose
goose -dir migrations postgres "$DB_URL" up

# Or using golang-migrate
migrate -path migrations -database "$DB_URL" up

# Or manually
psql -d yourdb -f migrations/001_initial_schema.sql
```

### 2. Use in your app

```go
package main

import (
    "database/sql"
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    _ "github.com/lib/pq"
    "github.com/tendant/simple-idm-slim/idm"
)

func main() {
    db, _ := sql.Open("postgres", "postgres://localhost/myapp?sslmode=disable")

    // Create IDM instance (validates schema exists)
    auth, err := idm.New(idm.Config{
        DB:        db,
        JWTSecret: "your-secret-key-at-least-32-characters",
    })
    if err != nil {
        log.Fatal(err) // Fails if migrations haven't been run
    }

    r := chi.NewRouter()
    r.Mount("/auth", auth.Router())
    log.Fatal(http.ListenAndServe(":8080", r))
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Register user |
| POST | `/login` | Login |
| POST | `/refresh` | Refresh token |
| POST | `/logout` | Logout |
| POST | `/logout/all` | Logout all sessions (protected) |
| GET | `/me` | Get profile (protected) |
| PATCH | `/me` | Update profile (protected) |
| GET | `/google/start` | Start Google OAuth (if configured) |
| GET | `/google/callback` | Google OAuth callback (if configured) |

## Mounting Options

### Chi Router (Recommended)

```go
r := chi.NewRouter()
r.Mount("/auth", auth.Router())

// Or mount auth and /me separately
r.Mount("/api/auth", auth.AuthRouter())
r.Mount("/api/user", auth.MeRouter())
```

### Standard Library

```go
mux := http.NewServeMux()
auth.Routes(mux, "/api/v1/auth")
```

## Protect Your Routes

```go
r := chi.NewRouter()
r.Mount("/auth", auth.Router())

r.Group(func(r chi.Router) {
    r.Use(auth.AuthMiddleware())

    r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
        user, _ := auth.GetUser(r)
        fmt.Fprintf(w, "Hello %s!", user.Email)
    })
})
```

## Google OAuth

```go
auth, _ := idm.New(idm.Config{
    DB:        db,
    JWTSecret: "your-secret-key-at-least-32-characters",
    Google: &idm.GoogleConfig{
        ClientID:     "your-google-client-id",
        ClientSecret: "your-google-client-secret",
        RedirectURI:  "http://localhost:8080/auth/google/callback",
    },
})
```

## Configuration

```go
idm.New(idm.Config{
    DB:              db,                    // *sql.DB (required)
    JWTSecret:       "...",                 // min 32 chars (required)
    JWTIssuer:       "my-app",              // default: "simple-idm"
    AccessTokenTTL:  30 * time.Minute,      // default: 15 minutes
    RefreshTokenTTL: 24 * time.Hour,        // default: 7 days
    Logger:          slog.Default(),        // default: JSON logger
    Google:          &idm.GoogleConfig{},   // optional
})
```

## API Reference

| Function | Description |
|----------|-------------|
| `idm.New(Config)` | Create IDM instance (validates schema) |
| `auth.Router()` | Chi router with all routes |
| `auth.AuthRouter()` | Chi router without /me |
| `auth.MeRouter()` | Chi router for /me only |
| `auth.Handler()` | http.Handler (for StripPrefix) |
| `auth.Routes(mux, prefix)` | Register on ServeMux |
| `auth.AuthMiddleware()` | JWT validation middleware |
| `auth.GetUser(r)` | Get current user from DB |
| `idm.GetUserID(r)` | Get user ID string |
| `idm.GetUserIDFromContext(ctx)` | Get user UUID |

## Database Migrations

Migrations are in `migrations/` folder. Use your preferred tool:

```bash
# Install goose (if using goose)
make install-goose

# Run migrations
make migrate-up

# Rollback
make migrate-down

# Status
make migrate-status
```

Set `DB_URL` environment variable or it defaults to `postgres://localhost/simple_idm?sslmode=disable`.

## Standalone Server

For testing or standalone deployment:

```bash
cp .env.example .env
make migrate-up
go run ./cmd/simple-idm
```

## License

MIT
