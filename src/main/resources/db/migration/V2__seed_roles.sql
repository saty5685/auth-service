-- V2__seed_roles.sql
-- Seed the four platform roles.
-- INSERT IGNORE — idempotent: safe to run multiple times (e.g. in dev resets).
-- These rows must exist before the application starts — services.*.roles
-- reference them at startup.

INSERT IGNORE INTO roles (name) VALUES
    ('ROLE_USER'),
    ('ROLE_MERCHANT'),
    ('ROLE_ADMIN'),
    ('ROLE_INTERNAL_SERVICE');
