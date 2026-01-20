# simple-idm-slim

A minimal, reliable identity service supporting email/password and Google OAuth authentication.

## Features

- Email + password authentication with Argon2id hashing
- Google OAuth authentication
- JWT access tokens + opaque refresh tokens
- Session management with token revocation
- User profile management
- Clean extension point for future 2FA support

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 14+

### Setup

1. Create a PostgreSQL database:

```sql
CREATE DATABASE simple_idm;
```

2. Run the migrations:

```bash
psql -d simple_idm -f migrations/001_initial_schema.sql
```

3. Copy and configure environment variables:

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Build and run:

```bash
go build -o simple-idm ./cmd/simple-idm
./simple-idm
```

## API Endpoints

### Public Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/password/register` | Register a new user |
| POST | `/v1/auth/password/login` | Login with email/password |
| GET | `/v1/auth/google/start` | Start Google OAuth flow |
| GET | `/v1/auth/google/callback` | Google OAuth callback |
| POST | `/v1/auth/refresh` | Refresh access token |
| POST | `/v1/auth/logout` | Logout (revoke session) |

### Protected Endpoints (require Bearer token)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/me` | Get current user profile |
| PATCH | `/v1/me` | Update current user profile |
| POST | `/v1/auth/logout/all` | Logout all sessions |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |

## Usage Examples

### Register a new user

```bash
curl -X POST http://localhost:8080/v1/auth/password/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123", "name": "John Doe"}'
```

### Login

```bash
curl -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123"}'
```

### Get user profile

```bash
curl http://localhost:8080/v1/me \
  -H "Authorization: Bearer <access_token>"
```

### Refresh token

```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

### Logout

```bash
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDR` | `0.0.0.0` | Server bind address |
| `SERVER_PORT` | `8080` | Server port |
| `DB_HOST` | `localhost` | Database host |
| `DB_PORT` | `5432` | Database port |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | `postgres` | Database password |
| `DB_NAME` | `simple_idm` | Database name |
| `DB_SSLMODE` | `disable` | Database SSL mode |
| `JWT_SECRET` | (required) | JWT signing secret |
| `JWT_ISSUER` | `simple-idm` | JWT issuer claim |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_TTL` | `168h` | Refresh token lifetime (7 days) |
| `GOOGLE_CLIENT_ID` | (optional) | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | (optional) | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | (optional) | Google OAuth redirect URI |

## Architecture

```
cmd/
  simple-idm/          # Main application entry point
internal/
  auth/                # Authentication services (password, google, session)
  config/              # Configuration loading
  domain/              # Domain types and errors
  http/                # HTTP layer
    features/          # Feature modules (password, google, session, me)
    middleware/        # HTTP middleware
  httputil/            # HTTP response utilities
  repository/          # Database repositories
migrations/            # SQL migrations
```

## Security

- Passwords hashed with Argon2id (OWASP recommended parameters)
- Session tokens stored as SHA-256 hashes
- JWT access tokens with configurable expiration
- HTTP-only cookies supported for web clients
- CSRF protection via OAuth state parameter

## License

MIT
