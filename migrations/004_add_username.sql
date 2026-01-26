-- +goose Up
-- Migration: 004_add_username
-- Description: Add optional username support for login

-- Add username column (optional, case-insensitive)
ALTER TABLE users ADD COLUMN username CITEXT;

-- Create unique index for username (allows multiple NULLs)
CREATE UNIQUE INDEX idx_users_username_unique ON users(username) WHERE username IS NOT NULL;

-- Add constraint for username format validation
ALTER TABLE users ADD CONSTRAINT username_format CHECK (
    username IS NULL OR username ~ '^[a-zA-Z0-9][a-zA-Z0-9_-]{2,29}$'
);

-- Create index for active users with username
CREATE INDEX idx_users_username_active ON users(username) WHERE deleted_at IS NULL AND username IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_users_username_active;
ALTER TABLE users DROP CONSTRAINT IF EXISTS username_format;
DROP INDEX IF EXISTS idx_users_username_unique;
ALTER TABLE users DROP COLUMN IF EXISTS username;
