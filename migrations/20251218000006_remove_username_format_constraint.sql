-- +goose Up
-- Migration: Remove username format constraint
-- Description: Allow host applications to define their own username policy

ALTER TABLE users DROP CONSTRAINT IF EXISTS username_format;

-- +goose Down
ALTER TABLE users ADD CONSTRAINT username_format CHECK (
    username IS NULL OR username ~ '^[a-zA-Z0-9][a-zA-Z0-9_-]{2,29}$'
);
