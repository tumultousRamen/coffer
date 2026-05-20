-- PRD 0010: sync-on-stale refresh transitions a credential to status='failed'
-- when the provider returns a permanent error (e.g. OAuth invalid_grant).
-- The reason string surfaces in REST responses and operator tooling, so it
-- needs its own column rather than living in metadata.
ALTER TABLE credentials ADD COLUMN validation_error TEXT NOT NULL DEFAULT '';
