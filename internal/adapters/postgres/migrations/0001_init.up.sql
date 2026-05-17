-- ADR 0005: two tables, no RLS, hard delete.
-- IDs are UUIDv7 (time-ordered, generated client-side via google/uuid).

CREATE TABLE tenants (
    user_id        UUID PRIMARY KEY,
    encrypted_dek  BYTEA       NOT NULL,
    dek_version    INT         NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    id                UUID        PRIMARY KEY,
    user_id           UUID        NOT NULL REFERENCES tenants(user_id),
    provider          TEXT        NOT NULL,
    label             TEXT        NOT NULL,
    secret_ciphertext BYTEA       NOT NULL,
    nonce             BYTEA       NOT NULL,
    dek_version       INT         NOT NULL,
    metadata          JSONB       NOT NULL DEFAULT '{}',
    status            TEXT        NOT NULL DEFAULT 'active',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX credentials_user_provider_label ON credentials (user_id, provider, label);
CREATE INDEX        credentials_user_provider       ON credentials (user_id, provider);
