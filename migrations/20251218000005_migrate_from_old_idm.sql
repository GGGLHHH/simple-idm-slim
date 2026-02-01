-- +goose Up
-- Migration: Migrate data from old IDM schema (idm.*) to simple-idm-slim (public.*)

-- Migrate users from idm.users to public.users
-- Keep the same UUIDs to maintain foreign key relationships in membership table
INSERT INTO public.users (id, email, email_verified, name, created_at, updated_at, deleted_at)
SELECT
    u.id,
    u.email,
    u.email_verified,
    u.name,
    u.created_at AT TIME ZONE 'UTC',
    u.last_modified_at AT TIME ZONE 'UTC',
    u.deleted_at AT TIME ZONE 'UTC'
FROM idm.users u
WHERE u.deleted_at IS NULL
ON CONFLICT (id) DO NOTHING;

-- Migrate passwords from idm.login to public.user_password
-- Note: idm.login.password is bytea (bcrypt hash), public.user_password.password_hash is text
INSERT INTO public.user_password (user_id, password_hash, password_updated_at)
SELECT
    u.id as user_id,
    encode(l.password, 'escape') as password_hash,
    COALESCE(l.password_updated_at AT TIME ZONE 'UTC', l.updated_at AT TIME ZONE 'UTC') as password_updated_at
FROM idm.users u
JOIN idm.login l ON u.login_id = l.id
WHERE u.deleted_at IS NULL
  AND l.deleted_at IS NULL
  AND l.password IS NOT NULL
ON CONFLICT (user_id) DO NOTHING;

-- +goose Down
-- Cannot safely rollback data migration
